import demistomock as demisto
from CommonServerPython import *  # lgtm [py/polluting-import]
from tld import get_tld, get_fld
from validate_email import validate_email
from urllib.parse import urlparse, parse_qs, unquote
import re


PROOFPOINT_PREFIXES = ['https://urldefense.proofpoint.com/v1/url?u=', 'https://urldefense.proofpoint.com/v2/url?u=']
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
    # Normalize: 1) [.] --> . 2) hxxp --> http 3) &amp --> & 4) http:\\ --> http://
    url = escaped_url.lower().replace('[.]', '.').replace('hxxp', 'http').replace('&amp;', '&')\
        .replace('http:\\\\', 'http://')
    # Normalize the URL with http prefix
    if url.find('http:') == 0 and url.find('http://') == -1:
        url = url.replace('http:', 'http://')
    if url.find('http') != 0 and url.find('ftp') != 0:
        return 'http://' + url
    return url


def get_fqdn(the_input):
    fqdn = None
    domain = get_tld(the_input, fail_silently=True, as_object=True)

    # handle fqdn if needed
    if domain:
        # get the subdomain using tld.subdomain
        subdomain = domain.subdomain
        if (subdomain):
            fqdn = "{}.{}".format(subdomain, domain.fld)

    return fqdn


def extract_fqdn_or_domain(the_input, is_fqdn=None, is_domain=None):
    is_url = None
    domain_from_mail = None
    is_email = validate_email(the_input)
    if is_email:
        # Take the entire part after the @ of the email
        domain_from_mail = the_input.split('@')[1]
    else:
        # Test if URL, else proceed as domain

        # Check if it is a Microsoft ATP Safe Link
        if re.match(ATP_LINK_REG, the_input):
            the_input = atp_get_original_url(the_input)
        # Check if it is a Proofpoint URL
        elif the_input.find(PROOFPOINT_PREFIXES[0]) == 0 or the_input.find(PROOFPOINT_PREFIXES[1]) == 0:
            the_input = proofpoint_get_original_url(the_input)
        # Not ATP Link or Proofpoint URL so just unescape
        else:
            the_input = unescape_url(the_input)
        if is_fqdn:
            is_url = indicator = get_fqdn(the_input)
        if is_domain:
            is_url = indicator = get_fld(the_input, fail_silently=True)

    # Extract domain itself from a potential subdomain
    if domain_from_mail or not is_url:
        full_domain = 'https://'
        full_domain += domain_from_mail if domain_from_mail else the_input
        # get_tld fails to parse subdomain since it is not URL, over-ride error by injecting protocol.
        if is_fqdn:
            indicator = get_fqdn(full_domain)
        if is_domain:
            indicator = get_fld(full_domain, fail_silently=True)

    # convert None to empty string if needed
    indicator = '' if not indicator else indicator
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
