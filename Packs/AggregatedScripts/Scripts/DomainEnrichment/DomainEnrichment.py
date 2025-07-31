import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum
from AggregatedCommandApiModule import *


class ContextPaths(Enum):
    DOMAIN_ENRICHMENT = "DomainEnrichment(" "val.Brand && val.Brand == obj.Brand && (" "val.Data && val.Data == obj.Data))"

    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    DOMAIN = Common.Domain.CONTEXT_PATH


CONTEXT_PATH = {"domain": Common.Domain.CONTEXT_PATH}
INDICATOR_PATH = {"domain": "Domain"}
INDICATOR_VALUE_FIELDS = {"domain": "Name"}

MAIN_KEYS = ["Address", "Name", "Brand", "Data", "DetectionEngines", "PositiveDetections", "Score"]
""" COMMAND CLASS """

""" COMMAND FUNCTION """


def domain_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False
):
    """
    Enriches Domain data with information from various integrations
    """
    indicator_type="domain"
    mapping = {"Data":"Data",
               "DetectionEngines":"DetectionEngines",
               "PositiveDetections":"PositiveDetections",
               "Score":"Score",
               "Brand":"Brand"}
    
    commands = [ReputationCommand(name="domain", args={"domain": data_list}, mapping=mapping),
                Command(name="core-get-domain-analytics-prevalence", args={"domain_name": data_list}, type=CommandType.internal),
                TIMCommand(mapping=mapping, indicator_context_path="Domain(")
    ]
    domain_reputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        indicator_value_field="Data",
        validate_input_function=lambda args: True,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="DomainEnrichment",
        args=demisto.args(),
        data={"domain": data_list}
    )
    return domain_reputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    data_list = argToList(args.get("data"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(domain_enrichment_script(data_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute DomainEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()