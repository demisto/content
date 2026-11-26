import ipaddress
import re
import socket
import traceback
from functools import reduce
from urllib.parse import urljoin, urlparse

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


REQUEST_TIMEOUT = 30
MAX_REDIRECTS = 5


def is_ip_internal_or_restricted(ip_str: str) -> bool:
    """
    Checks if an IP address string is internal, loopback, private, link-local,
    multicast, reserved, unspecified, or cloud metadata.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return False


def validate_url_safe(url: str, arg_name: str = "url") -> str:
    """
    Validates that a URL uses http or https and does not resolve or point to
    internal, private, loopback, or restricted addresses (SSRF prevention).
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"Invalid URL provided for '{arg_name}'.")

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Invalid scheme '{parsed.scheme}' in '{arg_name}'. Only HTTP and HTTPS URLs are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not extract hostname from '{arg_name}' URL: {url}")

    # Check if hostname directly represents an IP
    if is_ip_internal_or_restricted(hostname):
        raise ValueError(f"URL '{url}' in '{arg_name}' points to an internal or restricted IP address.")

    # Resolve hostname to verify destination IPs
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Unable to resolve hostname '{hostname}' for '{arg_name}': {e}")

    for info in addr_info:
        resolved_ip = str(info[4][0])
        if is_ip_internal_or_restricted(resolved_ip):
            raise ValueError(f"URL '{url}' in '{arg_name}' resolves to an internal or restricted IP address ({resolved_ip}).")

    return url


def safe_get(url: str, arg_name: str = "url") -> requests.Response:
    """
    Performs a GET request, validating the URL and every redirect hop
    against SSRF restrictions instead of blindly following redirects.
    """
    for _ in range(MAX_REDIRECTS + 1):
        validate_url_safe(url, arg_name)
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        location = response.headers.get("Location") if response.is_redirect else None
        if not location:
            return response
        url = urljoin(url, location)
    raise ValueError(f"Too many redirects (more than {MAX_REDIRECTS}) for '{arg_name}'.")


def ads(html, termlist):
    results: dict = {}
    tags = re.findall("<[^/][^>]*>", html)
    for item in termlist.split("\n"):
        if not item.strip():
            continue
        if item.startswith(("!", "[Adbl", "@@")):
            continue
        if item.startswith("###"):
            item = item[3:]
        if item.startswith("||"):
            item = item[2 : item.find("^$")]
        for t in tags:
            if item in t:
                results[item] = (results[item] + 1) if item in results else 1
    return results


def main():  # pragma: no cover
    try:
        url = demisto.args()["url"]
        easylist_url = demisto.args().get("easylist", "https://easylist.github.io/easylist/easylist.txt")

        r = safe_get(url, "url")
        reasy = safe_get(easylist_url, "easylist")
        res = ads(r.text, reasy.text)
        nicerRes = [{"URL": k, "Count": res[k]} for k in res]
        totalAds = reduce(lambda x, y: x + y["Count"], nicerRes, 0)
        demisto.results(
            {
                "Type": entryTypes["note"],
                "Contents": nicerRes,
                "ContentsFormat": formats["json"],
                "HumanReadable": tableToMarkdown("AD URLs", nicerRes) + "\nTotal: " + str(totalAds),
                "EntryContext": {"Ads": nicerRes, "URL(val.Data == obj.Data)": {"Data": url, "AdsCount": totalAds}},
            }
        )
    except Exception as e:
        demisto.debug(traceback.format_exc())
        return_error(f"Failed to execute URLNumberOfAds. Error:\n{e!s}", error=e)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
