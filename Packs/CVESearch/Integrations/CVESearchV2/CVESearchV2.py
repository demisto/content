import urllib3
from typing import Dict, Any, List, Union

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url: str, verify=False, proxy=False):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, headers=headers, verify=verify, proxy=proxy)

    def cve_latest(self, limit) -> List[Dict[str, Any]]:
        res = self._http_request(method='GET', url_suffix=f'/last/{limit}', timeout=60)
        return res

    def cve(self, cve_id) -> Dict[str, Any]:
        res: Dict[str, Any] = self._http_request(method='GET', url_suffix=f'cve/{cve_id}', timeout=60)
        return res or {}


def cve_to_context(cve) -> Dict[str, str]:
    """Returning a cve structure with the following fields:
    * ID: The cve ID.
    * CVSS: The cve score scale/
    * Published: The date the cve was published.
    * Modified: The date the cve was modified.
    * Description: the cve's description

        Args:
            cve: The cve response from CVE-Search web site
    Returns:
        The cve structure.
    """
    cvss = cve.get('cvss')
    return {
        'ID': cve.get('id', ''),
        'CVSS': cvss or 'N\\A',
        'Published': cve.get('Published', '').rstrip('Z'),
        'Modified': cve.get('Modified', '').rstrip('Z'),
        'Description': cve.get('summary', '')
    }


def test_module(client: Client, reliability: str):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        cve_latest_command(client, 1, reliability)
    except Exception as e:
        if "Read timed out." not in str(e):
            raise
    return 'ok', None, None


def cve_latest_command(client: Client, limit: int, reliability: str) -> List[CommandResults]:
    """Returns the 30 latest updated CVEs.
    Args:
         limit int: The amount of CVEs to display
         reliability: The reliability of the source.
    Returns:
         Latest 30 CVE details containing ID, CVSS, modified date, published date and description.
    """
    res = client.cve_latest(limit)
    command_results: List[CommandResults] = []
    for cve_details in res:
        data = cve_to_context(cve_details)
        indicator = generate_indicator(data, reliability)
        readable_output = tableToMarkdown('Latest CVEs', data)
        command_results.append(
            CommandResults(
                outputs_prefix='CVE',
                outputs_key_field='ID',
                outputs=data,
                readable_output=readable_output,
                raw_response=res,
                indicator=indicator
            )
        )

    if not res:
        command_results.append(
            CommandResults(
                readable_output='No results found'
            )
        )
    return command_results


def cve_command(client: Client, args: dict, reliability: str) -> Union[List[CommandResults], CommandResults]:
    """Search for cve with the given ID and returns the cve data if found.
    Args:
           client: Integration client
           args :The demisto args containing the cve_id
           reliability: The reliability of the source
    Returns:
        CVE details containing ID, CVSS, modified date, published date and description.
    """
    cve_id = args.get('cve_id', '')
    cve_ids = argToList(cve_id)
    command_results: List[CommandResults] = []

    for _id in cve_ids:
        if not valid_cve_id_format(_id):
            raise DemistoException(f'"{_id}" is not a valid cve ID')

        response = client.cve(_id)
        if not response:
            cr = CommandResults(readable_output=f'### No results found for cve {_id}')
        else:
            data = cve_to_context(response)
            indicator = generate_indicator(data, reliability)
            cr = CommandResults(
                outputs_prefix='CVE',
                outputs_key_field='ID',
                outputs=data,
                raw_response=response,
                indicator=indicator,
            )
        command_results.append(cr)

    return command_results


def generate_indicator(data: dict, reliability: str) -> Common.CVE:
    """
    Generating a single cve indicator with dbot score from cve data.
    Args:
        data: The cve data
        reliability: The reliability of the source

    Returns:
        A CVE indicator with dbotScore
    """
    cve_object = Common.CVE(
        id=data.get('ID'),
        cvss=data.get('CVSS'),
        published=data.get('Published'),
        modified=data.get('Modified'),
        description=data.get('Description'),
        dbot_score=Common.DBotScore(indicator=data.get('ID'),
                                    indicator_type=DBotScoreType.CVE,
                                    malicious_description=data.get('Description'),
                                    score=Common.DBotScore.NONE,
                                    reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(reliability))
    )
    return cve_object


def valid_cve_id_format(cve_id: str) -> bool:
    """Validates that the given cve_id is a valid cve ID.
     For more details see: https://cve.mitre.org/cve/identifiers/syntaxchange.html
    Args:
        cve_id: ID to validate
    Returns:
        True if cve_id is a valid cve ID else False
    """
    return bool(re.match(cveRegex, cve_id))


def main():
    params = demisto.params()
    proxy = params.get('proxy', False)
    use_ssl = not params.get('insecure', False)
    base_url = params.get('url', 'https://cve.circl.lu/api/')
    client = Client(base_url=base_url, verify=use_ssl, proxy=proxy)
    command = demisto.command()
    reliability = params.get('integration_reliability', '')

    LOG(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            return_outputs(*test_module(client, reliability))

        elif demisto.command() == 'cve-latest':
            return_results(cve_latest_command(client, demisto.args().get('limit', 30), reliability))

        elif demisto.command() == 'cve':
            return_results(cve_command(client, demisto.args(), reliability))

        else:
            raise NotImplementedError(f'{command} is not an existing CVE Search command')

    except Exception as err:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
