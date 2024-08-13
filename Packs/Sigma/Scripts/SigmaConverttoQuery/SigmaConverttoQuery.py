import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from sigma.rule import SigmaRule
from sigma import exceptions
from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.backends.qradar import QradarBackend
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.backends.elasticsearch import LuceneBackend

import json

SIEMS = {
    "xql": CortexXDRBackend(),
    "splunk": SplunkBackend(),
    "sentinel_one": SentinelOneBackend(),
    "qradar": QradarBackend(),
    "microsoft_defender": Microsoft365DefenderBackend(),
    "carbon_black": CarbonBlackBackend(),
    "elastic": LuceneBackend()
}

def get_sigma_dictionary(indicator: str) -> dict:
    """
    Find the Sigma rule dictionary for a given indicator value.

    Args:
        indicator (str): The indicator value to search for.

    Returns:
        dict: The Sigma rule dictionary.

    Raises:
        DemistoException: If the indicator is not found or Sigma dictionary cannot be loaded.
    """

    demisto.debug(f'Starting search for indicator: {indicator}')
    search_result = demisto.executeCommand('findIndicators', {'value': indicator})

    if isError(search_result):
        return_error(f'Failed to find indicator {indicator}. Error: {get_error(search_result)}')

    indicators = search_result[0]['Contents']

    if not indicators:
        return_error(f'No indicator found with value {indicator}.')

    indicator = indicators[0]

    try:
        sigma_dict = json.loads(indicator.get('CustomFields', {}).get('sigmaruleraw', ''))
        demisto.debug('Successfully loaded Sigma dictionary.')

    except Exception as e:
        return_error(f'Could not load Sigma dictionary - {e}')

    return sigma_dict

def main() -> None:
    """
    Main function to convert a Sigma rule indicator into a SIEM query.
    """

    indicator = demisto.args().get('indicator', '')

    if not indicator:
        return_error('You must provide an indicator.')

    try:
        siem = SIEMS[demisto.args()['SIEM'].lower()]
        demisto.debug(f'SIEM selected: {demisto.args()["SIEM"].lower()}')

    except KeyError:
        return_error(f'Unknown SIEM - "{demisto.callingContext["args"]["SIEM"]}"')

    # Convert Sigma rule to SIEM query
    rule = SigmaRule.from_dict(get_sigma_dictionary(indicator))

    try:
        query = siem.convert_rule(rule)[0]
        demisto.debug('Successfully converted Sigma rule to SIEM query.')

    except exceptions.SigmaTransformationError as e:
        query = f'ERROR:\n{e}'

    return_results(query)

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

