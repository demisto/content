from html import unescape
from typing import Tuple
from urllib.parse import urlparse, parse_qs, ParseResult, unquote

from CommonServerPython import *

ATP_REGEX = re.compile(r'(https://\w*|\w*)\.safelinks\.protection\.outlook\.com/.*\?url=')
FIREEYE_REGEX = re.compile(r'(https:\/\/\w*|\w*)\.fireeye\.com\/.*\/url\?k=')
PROOF_POINT_URL_REG = re.compile(r'https://urldefense(?:\.proofpoint)?\.(com|us)/(v[0-9])/')
HTTP = 'http'
PREFIX_TO_NORMALIZE = {
    'hxxp',
    'meow',
    'hXXp',
}
# Tuple of starts_with, does_not_start_with (if exists), replace to.
PREFIX_CHANGES: List[Tuple[str, Optional[str], str]] = [
    ('https:/', 'https://', 'https://'),
    ('http:/', 'http://', 'http://'),
    ('https:\\', 'https:\\\\', 'https://'),
    ('http:\\', 'http:\\\\', 'http://'),
    ('https:\\\\', None, 'https://'),
    ('http:\\\\', None, 'http://'),
]


def get_redirect_url_proof_point_v2(non_formatted_url: str, parse_results: ParseResult) -> str:
    """
    Extracts redirect URL from Proof Point V2.
    Args:
        non_formatted_url (str): Non formatted URL.
        parse_results (ParseResult): Parse results of the given URL.

    Returns:
        (str): Redirected URL from Proof Point.
    """
    url_: str = get_redirect_url_from_query(non_formatted_url, parse_results, 'u')
    trans = str.maketrans('-_', '%/')
    url_ = url_.translate(trans)
    return url_


def get_redirect_url_proof_point_v3(non_formatted_url: str) -> str:
    """
    Extracts redirect URL from Proof Point V3.
    Args:
        non_formatted_url (str): Non formatted URL.

    Returns:
        (str): Redirected URL from Proof Point.
    """
    url_regex = re.compile(r'v3/__(?P<url>.+?)__;(?P<enc_bytes>.*?)!')
    if match := url_regex.search(non_formatted_url):
        non_formatted_url = match.group('url')
    else:
        demisto.error(f'Could not parse Proof Point redirected URL. Returning original URL: {non_formatted_url}')
    return non_formatted_url


def get_redirect_url_from_query(non_formatted_url: str, parse_results: ParseResult, redirect_param_name: str) -> str:
    """
    Receives an ATP Safe Link URL, returns the URL the ATP Safe Link points to.
    Args:
        non_formatted_url (str): The raw URL. For debugging purposes.
        parse_results (str): ATP Safe Link URL parse results.
        redirect_param_name (str): Name of the redirect parameter.
    Returns:
        (str): The URL the ATP Safe Link points to.
    """
    query_params_dict: Dict[str, List[str]] = parse_qs(parse_results.query)
    if not (query_urls := query_params_dict.get(redirect_param_name, [])):
        demisto.error(f'Could not find redirected URL. Returning the original URL: {non_formatted_url}')
        return non_formatted_url
    if len(query_urls) > 1:
        demisto.debug(f'Found more than one URL query parameters for redirect in the given URL {non_formatted_url}\n'
                      f'Returning the first URL: {query_urls[0]}')
    url_: str = query_urls[0]
    return url_


def replace_protocol(url_: str) -> str:
    """
    Replaces URL protocol with expected protocol. Examples can be found in tests.
    Args:
        url_ (str): URL to replace the protocol by the given examples above.

    Returns:
        (str): URL with replaced protocol, if needed to replace, else the URL itself.
    """
    for prefix_to_normalize in PREFIX_TO_NORMALIZE:
        if url_.startswith(prefix_to_normalize):
            url_ = url_.replace(prefix_to_normalize, HTTP)
    lowercase_url = url_.lower()
    for starts_with, does_not_start_with, to_replace in PREFIX_CHANGES:
        if lowercase_url.startswith(starts_with) and (
                not does_not_start_with or not lowercase_url.startswith(does_not_start_with)):
            url_ = url_.replace(starts_with, to_replace)
    if url_.startswith('http:') and not url_.startswith('http:/'):
        url_ = url_.replace('http:', 'http://')
    if url_.startswith('https:') and not url_.startswith('https:/'):
        url_ = url_.replace('https:', 'https://')
    return url_


def search_for_redirect_url_in_first_query_parameter(parse_results: ParseResult) -> Optional[str]:
    """
    Returns a redirect URL if finds it under the assumption:
    1) The redirect URL is in first query parameter value.
    2) The value starts with http.

    If both terms exists, returns the value of the first parameter, else returns None.
    Args:
        parse_results (Str): Parse results of a non formatted URL.

    Returns:
        (Optional[str]): Redirected URL if satisfies above condition, None otherwise.
    """
    if not parse_results.query:
        return None
    # parse_results.query has a structure of <param1>=<param1-value>&<param2>=<param2-value>...
    # if there are no query params, then parse_results.query is ''.
    query_parameters: List[str] = parse_results.query.split('&')
    # Having at least one query parameter means that the len is at least 2, because first cell is empty given above
    # mentioned structure of <param1>=<param1-value>&<param2>=<param2-value>...
    if query_parameters:
        # First query parameter is of structure <param1>=<param1-value>
        first_query_parameter: List[str] = query_parameters[0].split('=')
        # Validation of unexpected split behaviour
        if not len(first_query_parameter) == 2:
            demisto.error(f'Unexpected parse of query parameter: {query_parameters[0]}: Parse: {first_query_parameter}')
            return None
        first_query_parameter_value: str = first_query_parameter[1]
        # Redirect URL according to the given assumption
        if first_query_parameter_value.startswith('http'):
            return first_query_parameter_value
    return None


def format_urls(non_formatted_urls: List[str]) -> List[Dict]:
    """
    Formats a single URL.
    Args:
        non_formatted_urls (List[str]): Non formatted URLs.

    Returns:
        (Set[str]): Formatted URL, with its expanded URL if such exists.
    """

    def format_single_url(non_formatted_url: str) -> List[str]:
        parse_results: ParseResult = urlparse(non_formatted_url)
        additional_redirect_url: Optional[str] = None
        if re.match(ATP_REGEX, non_formatted_url):
            non_formatted_url = get_redirect_url_from_query(non_formatted_url, parse_results, 'url')
        elif re.match(FIREEYE_REGEX, non_formatted_url):
            if '&amp;' in non_formatted_url:
                non_formatted_url = get_redirect_url_from_query(non_formatted_url, parse_results, 'amp;u')
            else:
                non_formatted_url = get_redirect_url_from_query(non_formatted_url, parse_results, 'u')
        elif match := PROOF_POINT_URL_REG.search(non_formatted_url):
            proof_point_ver: str = match.group(2)
            if proof_point_ver == 'v3':
                non_formatted_url = get_redirect_url_proof_point_v3(non_formatted_url)
            elif proof_point_ver == 'v2':
                non_formatted_url = get_redirect_url_proof_point_v2(non_formatted_url, parse_results)
            else:
                non_formatted_url = get_redirect_url_from_query(non_formatted_url, parse_results, 'u')
        else:
            additional_redirect_url = search_for_redirect_url_in_first_query_parameter(parse_results)
        # Common handling for unescape and normalizing
        non_formatted_url = unquote(unescape(non_formatted_url.replace('[.]', '.')))
        formatted_url = replace_protocol(non_formatted_url)
        return [formatted_url, additional_redirect_url] if additional_redirect_url else [formatted_url]

    formatted_urls_groups = [format_single_url(url_) for url_ in non_formatted_urls]
    return [{
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': urls,
        'EntryContext': {'URL': urls} if urls else {}
    } for urls in formatted_urls_groups]


def main():
    try:
        formatted_urls_groups: List[Dict] = format_urls(argToList(demisto.args().get('input')))
        for formatted_urls_group in formatted_urls_groups:
            demisto.results(formatted_urls_group)
    except Exception as e:  # pragma: no cover
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute FormatURL. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
