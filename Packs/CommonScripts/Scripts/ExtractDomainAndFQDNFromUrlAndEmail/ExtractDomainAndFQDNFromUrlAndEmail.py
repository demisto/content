import demistomock as demisto
from CommonServerPython import *  # noqa: F401
from tld import get_tld, Result
from urllib.parse import urlparse, parse_qs, unquote
import re

PROOFPOINT_PREFIXES = ['https://urldefense.proofpoint.com/',
                       "https://urldefense.com/"]
ATP_LINK_REG = r'(https:\/\/\w*|\w*)\.safelinks\.protection\.outlook\.com/'
DOMAIN_REGEX = r"(?i)(?P<scheme>(?:http|ftp|hxxp)s?(?:://|-3A__|%3A%2F%2F))?(?P<domain>(?:[\w\-–_]+(?:\.|\[\.\]))+[^\W\d_]{2,})(?:[_/\s\"',)\]}>]|[.]\s?|%2F|.?$)"  # noqa: E501, RUF001


def atp_get_original_url(safe_url):  # pragma: no cover
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


def proofpoint_get_original_url(safe_url):  # pragma: no cover
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
    # Normalize: 1) [.] --> . 2) hxxp --> http 3) &amp --> & 4) http:\\ --> http://
    url = escaped_url.lower().replace('[.]', '.').replace('&amp;', '&') \
        .replace('http:\\\\', 'http://')
    # Normalize the URL with http prefix
    if url.find('http:') == 0 and url.find('http://') == -1:
        url = url.replace('http:', 'http://')
    if url.find('http') != 0 and url.find('ftp') != 0:
        return 'http://' + url
    return url


def get_fqdn(input_url: str) -> str | None:
    fqdn = ''
    domain_info = get_tld(input_url, fail_silently=True, as_object=True, fix_protocol=True) or \
        get_tld(input_url, fail_silently=True, as_object=True)

    if domain_info and domain_info.tld != 'onion':  # type: ignore[union-attr]
        # Weve removed the filter for "zip" as it is now a valid gTLD by Google
        if not isinstance(domain_info, Result):
            raise TypeError(f"Expected to get a Result object but got {type(domain_info)}")

        subdomain = domain_info.subdomain  # get the subdomain using tld.subdomain

        if subdomain:
            fqdn = f"{subdomain}.{domain_info.fld}"

        else:
            fqdn = domain_info.fld

    return fqdn


def pre_process_input(the_input):
    the_input = the_input.removesuffix('.')
    the_input = the_input.removeprefix('/')

    match = re.search(DOMAIN_REGEX, the_input)
    if match:
        the_input = match.group('domain')

    return the_input


def check_if_known_url(the_input):
    # Check if it is a Microsoft ATP Safe Link
    if re.match(ATP_LINK_REG, the_input):
        return ''
    # Check if it is a Proofpoint URL
    elif the_input.find(PROOFPOINT_PREFIXES[0]) == 0 or the_input.find(PROOFPOINT_PREFIXES[1]) == 0:
        return ''

    return the_input


def extract_fqdn(the_input):
    the_input = unquote(the_input)
    if the_input.endswith("@"):
        return ''
    if not the_input[0].isalnum():
        the_input = the_input[1:]
    the_input = check_if_known_url(the_input)
    # pre-processing the input, removing excessive characters
    the_input = pre_process_input(the_input)

    # Not ATP Link or Proofpoint URL so just unescape
    the_input = unquote(the_input)
    the_input = unescape_url(the_input)

    if indicator := get_fqdn(the_input):
        indicator = ".".join([re.sub("[^\w-]", "", part) for part in indicator.split(".")])
    return indicator


def main():
    try:
        the_input = demisto.args().get('input')

        # argToList returns the argument as is if it's already a list so no need to check here
        the_input = argToList(the_input)
        entries_list = []
        # Otherwise assumes it's already an array
        for item in the_input:
            input_entry = {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["json"],
                "Contents": [extract_fqdn(item)],
                "EntryContext": {"Domain": item}
            }
            if input_entry.get("Contents") == ['']:
                input_entry['Contents'] = []
            entries_list.append(input_entry)
        if entries_list:
            demisto.results(entries_list)
        else:
            # Return empty string so it wouldn't create an empty domain indicator.
            demisto.results('')

    except Exception as e:
        return_error(
            f'Failed to execute the automation. Error: \n{str(e)}'
        )


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
