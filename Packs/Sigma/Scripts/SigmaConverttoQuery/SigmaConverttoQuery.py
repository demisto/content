
from sigma import exceptions
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.backends.cortexxdr import CortexXDRBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.backends.qradar import QradarBackend
from sigma.backends.sentinelone import SentinelOneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.rule import SigmaRule

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SIEMS = {
    "xql": CortexXDRBackend(),
    "splunk": SplunkBackend(),
    "sentinel_one": SentinelOneBackend(),
    "qradar": QradarBackend(),
    "microsoft_defender": Microsoft365DefenderBackend(),
    "carbon_black": CarbonBlackBackend(),
    "elastic": LuceneBackend()
}


def get_sigma_dictionary(indicator_name: str) -> str:
    """
    Find the Sigma rule dictionary for a given indicator value.

    Args:
        indicator (str): The indicator value to search for.

    Returns:
        dict: The Sigma rule dictionary.

    Raises:
        DemistoException: If the indicator is not found or Sigma dictionary cannot be loaded.
    """

    try:
        demisto.debug(f'Starting search for indicator: {indicator_name}')
        indicator = execute_command('findIndicators', {'query': f'value:"{indicator_name}" and type:"Sigma Rule"'})

        if not indicator:
            return_error(f'No indicator found with value "{indicator_name}".')

        sigma = indicator[0].get('CustomFields', {}).get('sigmaruleraw', '')  # type: ignore

    except DemistoException as e:
        return_error(f'XSOAR encountered an error - {e}')

    except Exception as e:
        return_error(f'Could not load Sigma dictionary - {e}')

    return sigma


def main() -> None:
    """
    Main function to convert a Sigma rule indicator into a SIEM query.
    """

    args = demisto.args()
    indicator = args.get('indicator', '')

    if not indicator:
        return_error('You must provide an indicator.')

    try:
        siem_name = args['SIEM'].lower()
        siem = SIEMS[siem_name]
        demisto.debug(f'SIEM selected: {args["SIEM"].lower()}')

        rule = SigmaRule.from_yaml(get_sigma_dictionary(indicator))   # Convert Sigma rule to SIEM query

        query = siem.convert_rule(rule)[0]
        demisto.debug('Successfully converted Sigma rule to SIEM query.')

    except exceptions.SigmaTransformationError as e:
        query = f'ERROR:\n{e}'

    except KeyError:
        return_error(f'Unknown SIEM - "{demisto.callingContext["args"]["SIEM"]}"')

    except Exception as e:
        return_error(f'Error - {e}')

    return_results(CommandResults(outputs_prefix="Sigma",
                                  outputs={"query": query, "name": rule.title, "format": f"{siem_name}"},
                                  readable_output=query))


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
