import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

RECURSION_LIMIT = 10

UNSHORTEN_ME_URL = 'https://unshorten.me/json/'
HEADERS_FOR_UNSHORTEN_ME = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive',
}


def get_requests(client: BaseClient, url: str, count=0) -> str:
    count += 1
    while count <= RECURSION_LIMIT:
        try:
            resp = client._http_request(method='GET', full_url=url, resp_type='response', retries=3,
                                        allow_redirects=False)
            if (resp.status_code // 100 == 3) and (_url := resp.headers.get('location')):
                return get_requests(client, _url, count)
            return resp.url
        except Exception as e:
            if 'requests.exceptions.ConnectionError' in str(e):
                demisto.debug(f'ResolveShortenedURL: The following error: {str(e)}'
                              f' has occurred while trying to connect to: {url}')
                return f'An error occurred while trying to connect to the following URL: {url}'
            raise DemistoException(e)
    else:
        demisto.debug(
            f'ResolveShortenedURL: max retries ({RECURSION_LIMIT}) exceeded. Latest URL found: {url}')
        return url


def unshorten_using_requests(client: BaseClient, url: str) -> CommandResults:
    resolved_url = get_requests(client, url)

    return CommandResults(
        outputs_prefix='URL.Data',
        readable_output=tableToMarkdown('Shorten URL results', {
            'Shortened URL': url,
            'Resolved URL': resolved_url,
        }),
        outputs=[resolved_url],
    )


def unshorten_using_unshorten_me(client: BaseClient, url: str) -> Union[CommandResults, str]:
    resp = client._http_request('GET', url_suffix=url, headers=HEADERS_FOR_UNSHORTEN_ME)

    if resp.get('success'):
        resolved_url = resp.get('resolved_url')
        shortened_url = resp.get('requested_url')
        usage_count = resp.get('usage_count')

        return CommandResults(
            outputs_prefix='URL.Data',
            readable_output=tableToMarkdown('Shorten URL results', {
                'Shortened URL': shortened_url,
                'Resolved URL': resolved_url,
                'Usage count': usage_count,
            }),
            outputs=[resolved_url],
            raw_response=resp,
        )
    return 'Provided URL could not be un-shortened'


def main():
    try:
        args: dict = demisto.args()
        url = args['url']
        use_api = argToBoolean(args.get('use_unshorten_me', True))
        base_url = UNSHORTEN_ME_URL if use_api else ''
        client = BaseClient(base_url, verify=False)

        if use_api:
            return_results(unshorten_using_unshorten_me(client, url))
        else:
            return_results(unshorten_using_requests(client, url))
    except Exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ResolveShortenedURL. Error: {traceback.format_exc()}')


if __name__ in ('__builtin__', 'builtins', '__main__'):  # pragma: no cover
    main()
