
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Any
import traceback
from bs4 import BeautifulSoup
from operator import attrgetter
import xmltodict
''' STANDALONE FUNCTION '''


def webscrap_html(page_html: str, navigator_tree: str):
    soup = BeautifulSoup(page_html, 'html.parser')
    return attrgetter(navigator_tree)(soup)


''' STANDALONE FUNCTION '''


class Client(BaseClient):

    def webscrap_url(self, params=None, headers=None, navigator_tree='body'):
        if params is None:
            params = {}
        response = self._http_request('get', params=params,
                                      headers=headers, resp_type='response')
        return webscrap_html(response.text, navigator_tree)


''' COMMAND FUNCTION '''


def webscraper_command(args: Dict[str, Any]) -> CommandResults:

    page_html = args.get('page_html', None)
    page_url = args.get('page_url', None)
    headers = args.get('headers', None)
    params = args.get('params', None)
    navigator_tree = args.get('navigator_tree', 'body')

    verify_certificate = not args.get('insecure', False)

    if page_html:
        results = webscrap_html(page_html=page_html, navigator_tree=navigator_tree)
    elif page_url:
        client = Client(page_url, verify=verify_certificate)
        results = client.webscrap_url(headers=headers, params=params, navigator_tree=navigator_tree)
        print(xmltodict.parse(results))
    else:
        raise ValueError('Please use page_url or page_html arguments to start scraping')

    return CommandResults(
        outputs_prefix='WebScraper.Pages',
        outputs_key_field='',
        outputs=results
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(webscraper_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute WebScraper. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
