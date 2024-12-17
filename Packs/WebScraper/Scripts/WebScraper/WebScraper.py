import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

from typing import Any
import traceback
from bs4 import BeautifulSoup
from operator import attrgetter
import xmltodict
''' STANDALONE FUNCTION '''


def nested_dict_pairs_iterator(dict_obj):
    for key, value in dict_obj.items():
        if isinstance(value, dict):
            for pair in nested_dict_pairs_iterator(dict(value)):
                yield pair

        else:
            yield {key: value}


def webscrap_html(page_html: str, navigator_tree: str):
    scrap_xml = attrgetter(navigator_tree)(BeautifulSoup(page_html, 'html.parser'))

    scrap_dict = dict(xmltodict.parse(scrap_xml.__str__()))
    results = []
    for pair in nested_dict_pairs_iterator(scrap_dict):
        results.append(pair)
    return results


''' STANDALONE FUNCTION '''


class Client(BaseClient):

    def webscrap_url(self, params=None, headers=None, navigator_tree='body'):
        if params is None:
            params = {}
        response = self._http_request('get', params=params,
                                      headers=headers, resp_type='response')
        return webscrap_html(response.text, navigator_tree)


''' COMMAND FUNCTION '''


def webscraper_command(args: dict[str, Any]) -> CommandResults:

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
    else:
        raise ValueError('Please use page_url or page_html arguments to start scraping')

    content_outputs = {
        "Tree": results
    }
    return CommandResults(
        outputs_prefix='WebScraper',
        outputs_key_field='',
        outputs=content_outputs,
        readable_output="Scrapping completed!"
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
