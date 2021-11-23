
import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]
from tld import get_tld, get_fld, Result
from urllib.parse import urlparse, parse_qs, unquote
import re

PROOFPOINT_PREFIXES = ['https://urldefense.proofpoint.com/v1/url?u=', 'https://urldefense.proofpoint.com/v2/url?u=',
                       "https://urldefense.com/v3/__"]
ATP_LINK_REG = r'(https:\/\/\w*|\w*)\.safelinks\.protection\.outlook\.com\/.*\?url='


def atp_get_original_url(safe_url):
    split_url = urlparse(safe_url)
    query = split_url.query
    query_dict = parse_qs(query)
    encoded_url_list = query_dict.get('url', [])
    encoded_url = encoded_url_list[0] if len(encoded_url_list) >= 1 else None
    if not encoded_url:
        error_msg = 'Could not decode ATP Safe Link. Returning original URL.'
        demisto.info(error_msg)
        return safe_url
    decoded_url = unquote(encoded_url)
    return decoded_url


def proofpoint_get_original_url(safe_url):
    if safe_url.startswith(PROOFPOINT_PREFIXES[2]):
        safe_url = safe_url.replace(PROOFPOINT_PREFIXES[2], '')
        return safe_url
    regex = r'&.*$'
    split_url = urlparse(safe_url)
    query = split_url.query
    query_dict = parse_qs(query)
    encoded_url_list = query_dict.get('u', [])
    encoded_url = encoded_url_list[0] if len(encoded_url_list) >= 1 else None
    clean = encoded_url.replace('-', '%').replace('_', '/').replace(regex, '') if encoded_url else None
    clean = unquote(clean) if clean else None
    return clean


def unescape_url(escaped_url):
    return escaped_url.lower().replace('[.]', '.').replace('&amp;', '&')


def get_fqdn(the_input):
    fqdn = None
    domain = get_tld(the_input, fail_silently=True, as_object=True, fix_protocol=True)

    # handle fqdn if needed
    if domain and isinstance(domain, Result):
        # get the subdomain using tld.subdomain
        subdomain = domain.subdomain
        if subdomain:
            fqdn = "{}.{}".format(subdomain, domain.fld)

    return fqdn


def extract_fqdn_or_domain(the_input, is_fqdn=None, is_domain=None):
    # Check if it is a Microsoft ATP Safe Link
    if re.match(ATP_LINK_REG, the_input):
        the_input = atp_get_original_url(the_input)
    # Check if it is a Proofpoint URL
    elif the_input.find(PROOFPOINT_PREFIXES[0]) == 0 or the_input.find(PROOFPOINT_PREFIXES[1]) == 0 or \
            the_input.find(PROOFPOINT_PREFIXES[2]) == 0:
        the_input = proofpoint_get_original_url(the_input)
    # Not ATP Link or Proofpoint URL so just unescape
    else:
        the_input = unescape_url(the_input)
    if is_fqdn:
        indicator = get_fqdn(the_input)
    if is_domain:
        indicator = get_fld(the_input, fail_silently=True, fix_protocol=True)

    # convert None to empty string if needed
    if (indicator and get_tld(indicator, fail_silently=True, fix_protocol=True) == 'zip') or not indicator:
        indicator = ''

    return indicator


def main():
    the_input = demisto.args().get('input')

    # argToList returns the argument as is if it's already a list so no need to check here
    the_input = argToList(the_input)
    entries_list = []
    # Otherwise assumes it's already an array
    for item in the_input:
        input_entry = {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": [extract_fqdn_or_domain(item, is_fqdn=True), extract_fqdn_or_domain(item, is_domain=True)]
        }
        if input_entry.get("Contents") == ['', '']:
            input_entry['Contents'] = []
        entries_list.append(input_entry)
    if entries_list:
        demisto.results(entries_list)
    else:
        # Return empty string so it wouldn't create an empty domain indicator.
        demisto.results('')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
