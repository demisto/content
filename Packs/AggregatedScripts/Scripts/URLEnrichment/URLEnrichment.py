import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from enum import Enum
from AggregatedCommandApiModule import *


class ContextPaths(Enum):
    URL_ENRICHMENT = "URLEnrichment(" "val.Brand && val.Brand == obj.Brand && (" "val.Data && val.Data == obj.Data))"

    DBOT_SCORE = Common.DBotScore.CONTEXT_PATH
    URL = Common.URL.CONTEXT_PATH


CONTEXT_PATH = {"url": Common.URL.CONTEXT_PATH, "domain": Common.Domain.CONTEXT_PATH}
INDICATOR_PATH = {"url": "URL", "domain": "Domain", "ip": "IP"}
INDICATOR_VALUE_FIELDS = {"url": "Data", "domain": "Name", "ip": "Address"}

MAIN_KEYS = ["Address", "Name", "Brand", "Data", "DetectionEngines", "PositiveDetections", "Score"]
""" COMMAND CLASS """

""" COMMAND FUNCTION """


def url_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False, indicator_type="url"
):
    """
    Enriches URL data with information from various integrations
    """
    indicator_mapping = {"Data":"Data",
               "DetectionEngines":"DetectionEngines",
               "PositiveDetections":"PositiveDetections",
               "Score":"Score",
               "Brand":"Brand"}
    
    commands = [ReputationCommand(name="url",args={"url": data}, mapping=indicator_mapping, indicator_context_path="URL(") for data in data_list]
    commands.extend([
        Command(name="wildfire-get-verdict", args={"url": data_list}, command_type=CommandType.internal, brand="WildFire-v2", mapping={"WildFire.Verdicts(val.url && val.url == obj.url)":"WildFireVerdicts(val.url && val.url == obj.url)[]"})])
    urlreputation = ReputationAggregatedCommand(
        brands = enrichment_brands,
        verbose=verbose,
        commands = commands,
        indicator_type="url",
        indicator_value_field="Data",
        validate_input_function=lambda args: True,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=demisto.args(),
        data=data_list,
        indicator_mapping=indicator_mapping,
        indicator_context_path="URL(",
    )
    return urlreputation.aggregated_command_main_loop()
    

""" MAIN FUNCTION """


def main():
    args = demisto.args()
    data_list = argToList(args.get("data"))
    indicator_type = "URL"
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands"))
    additional_fields = argToBoolean(args.get("additional_fields", False))

    try:
        return_results(url_enrichment_script(data_list, external_enrichment, verbose, brands, additional_fields, indicator_type))
    except Exception as ex:
        return_error(f"Failed to execute URLEnrichment. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()