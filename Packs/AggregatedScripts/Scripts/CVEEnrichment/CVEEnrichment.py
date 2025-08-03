import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum
from AggregatedCommandApiModule import *


class ContextPaths(Enum):
    CVE_ENRICHMENT = "CVEEnrichment(" "val.Brand && val.Brand == obj.Brand && (" "val.Data && val.Data == obj.Data))"

    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    CVE = Common.CVE.CONTEXT_PATH


CONTEXT_PATH = {"cve": Common.CVE.CONTEXT_PATH}
INDICATOR_PATH = {"cve": "CVE"}
INDICATOR_VALUE_FIELDS = {"cve": "Name"}

MAIN_KEYS = ["Address", "Name", "Brand", "Data", "DetectionEngines", "PositiveDetections", "Score"]
""" COMMAND CLASS """

""" COMMAND FUNCTION """


def cve_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False
):
    """
    Enriches CVE data with information from various integrations
    """
    indicator_type="cve"
    mapping = {"Data":"Data",
               "DetectionEngines":"DetectionEngines",
               "PositiveDetections":"PositiveDetections",
               "Score":"Score",
               "Brand":"Brand"}
    
    commands = [ReputationCommand(name="cve",args={"cve": data}, mapping=mapping, indicator_context_path="CVE(") for data in data_list]
    commands.append(TIMCommand(mapping=mapping, indicator_context_path="CVE("))
    cve_reputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        indicator_value_field="Data",
        validate_input_function=lambda args: True,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="CVEEnrichment",
        args=demisto.args(),
        data={"cve": data_list}
    )
    return cve_reputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    data_list = argToList(args.get("cve"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(cve_enrichment_script(data_list, external_enrichment, verbose, brands, additional_fields))
    except Exception as ex:
        return_error(f"Failed to execute CVEEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()