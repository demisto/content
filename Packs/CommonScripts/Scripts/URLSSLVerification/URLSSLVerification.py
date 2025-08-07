import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

NON_SSL_PREFIX = "http"
SSL_PREFIX = "https"
VENDOR = "URL SSL Verification"
SUSPICIOUS_SCORE = 2
UNKNOWN_SCORE = 0
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


def request_get_wrap(url: str, allow_redirects=True):
    """
    Wrapper around requests.get to handle SSL and connection errors,
    and optionally capture the full redirect chain.
    Return message with Failure information.
    Args:
        url (str): The URL to fetch.
        allow_redirects (bool): Whether to follow redirects.

    Returns:
        tuple:
            - message (dict): Result message with Vendor and Description.
            - redirect_chain (list): List of response objects from the redirect chain (if any).
    """
    message = {}
    redirect_chain = []
    try:
        response = requests.get(url, timeout=5, allow_redirects=allow_redirects)
        if allow_redirects:
            redirect_chain = response.history + [response]
    except requests.exceptions.SSLError:
        message = {"Vendor": VENDOR, "Description": "SSL Certificate verification failed"}
    except requests.exceptions.RequestException:
        message = {"Vendor": VENDOR, "Description": "Failed to establish a new connection with the URL"}

    return message, redirect_chain


def verify_ssl_certificate(url: str):
    """
    Verifies the SSL certificate of a given URL by following any redirects and checking the certificate for each redirected URL.
    If all of the redirect chain are all http return malicious message.

    Args:
        url (str): The URL to verify.

    Returns:
        dict: A dictionary with  Information and a description of the issue if the SSL certificate verification.
              Returns None if the verification is successful.
    """
    message, redirect_chain = request_get_wrap(url, allow_redirects=True)
    if message:
        return message

    is_all_http = True
    for resp in redirect_chain:
        redirected_url = resp.url
        if not redirected_url.startswith(SSL_PREFIX):
            continue
        is_all_http = False
        message, _ = request_get_wrap(url, allow_redirects=True)
        if message:
            return message

    if is_all_http:
        return {"Vendor": VENDOR, "Description": "The URL is not secure under SSL"}

    return None


def mark_http_as_suspicious(set_http_as_suspicious):
    # Could be None in previous playbooks that using this automation.
    return set_http_as_suspicious != "false"


def main():
    url_arg = demisto.get(demisto.args(), "url")
    urls = arg_to_list_with_regex(url_arg)

    set_http_as_suspicious = demisto.args().get("set_http_as_suspicious")

    url_list = []

    dbot_score = []
    for url in urls:
        url_obj = {"Data": url}
        malicious = verify_ssl_certificate(url)

        if malicious:
            url_obj["Verified"] = False
            url_obj["Malicious"] = malicious
        else:
            url_obj["Verified"] = True

        score = UNKNOWN_SCORE
        
        if mark_http_as_suspicious(set_http_as_suspicious) and not url.startswith(SSL_PREFIX):
            score = SUSPICIOUS_SCORE
        elif malicious:
            score = SUSPICIOUS_SCORE

        dbot_score.append({"Indicator": url,
                           "Type": "url",
                           "Vendor": VENDOR,
                           "Score": score,
                           })

        url_list.append(url_obj)

    preview_list = [
        {
            "URL": url["Data"],
            "Verified": url["Verified"],
            "Description": demisto.get(url, "Malicious.Description") or "SSL certificate is verified",
        }
        for url in url_list
    ]
    entry_context = {"URL": url_list, "DBotScore": dbot_score}
    return_results(CommandResults(
        readable_output=tableToMarkdown(name="URL SSL Verification",
                                        t=preview_list,
                                        headers=["URL", "Verified", "Description"]),
        outputs=entry_context,
        outputs_key_field="URL.Data")
    )


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
