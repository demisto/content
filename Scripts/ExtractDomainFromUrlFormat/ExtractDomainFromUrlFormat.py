import demistomock as demisto
from CommonServerPython import *
from tld import get_tld
from validate_email import validate_email
from urlparse import urlparse, parse_qs
from urllib import unquote
import re

PROOFPOINT_PREFIXES = ['https://urldefense.proofpoint.com/v1/url?u=', 'https://urldefense.proofpoint.com/v2/url?u=']
ATP_LINK_REG = r'(https:\/\/\w*|\w*)\.safelinks\.protection\.outlook\.com\/\?url='


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


def get_tld_or_fqdn(the_input, isFQDNextract):
    fqdn = None
    domain = get_tld(the_input, fail_silently=True, as_object=True)

    # handle fqdn if needed
    if isFQDNextract and domain:
        # get the subdomain using tld.subdomain
        subdomain = domain.subdomain
        if (subdomain):
            fqdn = "{}.{}".format(subdomain, str(domain))

    return domain, fqdn


def extract_domain(the_input, isFQDNextract):
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

        domain, fqdn = get_tld_or_fqdn(the_input, isFQDNextract)

    # Extract domain itself from a potential subdomain
    if domain_from_mail or not domain:
        full_domain = 'https://'
        full_domain += domain_from_mail if domain_from_mail else the_input
        # get_tld fails to parse subdomain since it is not URL, over-ride error by injecting protocol.
        domain, fqdn = get_tld_or_fqdn(full_domain, isFQDNextract)

    # convert None to empty string if needed
    result = domain if not isFQDNextract else fqdn
    result = '' if not result else str(result)
    if type(result) == unicode:
        result = result.encode('utf-8', errors='ignore')
    return result


def main():
    results = []
    the_input = demisto.args().get('input')
    isFQDNextract = demisto.args().get('extractFQDN')

    # argToList returns the argument as is if it's already a list so no need to check here
    the_input = argToList(the_input)

    # Otherwise assumes it's already an array
    for item in the_input:
        results.append(extract_domain(item, isFQDNextract == 'true'))
    demisto.results(results)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
