from CommonServerPython import *
from typing import Any


''' COMMAND FUNCTION '''


def add_domain_riskscore_to_context(args: dict[str, Any]) -> CommandResults:

    domaintools_data = args['domaintools_data']

    domain_name = domaintools_data.get("Name")
    domain_risk_score = domaintools_data.get(
        "Analytics", {}).get("OverallRiskScore")

    result = {"Name": domain_name, "OverallRiskScore": domain_risk_score}

    return CommandResults(
        outputs_prefix='AddDomainRiskScoreToContext.HighRiskPivotedDomains',
        outputs_key_field='Name',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(add_domain_riskscore_to_context(demisto.args()))
    except Exception as ex:
        return_error(
            f'Failed to execute AddDomainRiskScoreToContext. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
