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

DBOT_SCORE_TO_VERDICT = {
    0: "Unknown",
    1: "Benign",
    2: "Suspicious",
    3: "Malicious",
}

MAIN_KEYS = ["Address", "Name", "Brand", "Data", "DetectionEngines", "PositiveDetections", "Score"]
""" COMMAND CLASS """

""" COMMAND FUNCTION """


def url_enrichment_script(
    data_list, external_enrichment=False, verbose=False, enrichment_brands=None, additional_fields=False, indicator_type="url"
):
    """
    Enriches URL data with information from various integrations
    """
    mapping = {"Data":"Data",
               "DetectionEngines":"DetectionEngines",
               "PositiveDetections":"PositiveDetections",
               "Score":"Score",
               "Brand":"Brand"}
    
    commands = [ReputationCommand(name="url", args={"url": data_list}, mapping=mapping),
                Command(name="wildfire-get-verdict", args={"url": data_list}, direct_mapping="WildFire.Verdicts(val.url && val.url == obj.url)")]
    urlreputation = ReputationAggregatedCommand(
        main_keys={"Data":"Data",
                   "DetectionEngines":"DetectionEngines",
                   "PositiveDetections":"PositiveDetections",
                   "Score":"Score",
                   "Brand":"Brand"},
        brands = enrichment_brands,
        verbose=True,
        commands = commands,
        validate_input_function=lambda args: True,
        additional_fields=True,
        external_enrichment=True,
        indicator_path="URL(",
        indicator_value_field="Data",
        context_path="URL",
        args=demisto.args(),
        data={"url":data_list}
        
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