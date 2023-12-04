from CommonServerPython import *


def get_related_indicators(addintional_indicators: str = '') -> list[str]:
    related_indicators = addintional_indicators.strip(
        '[]').replace('"', '').split(',')
    # Remove leading and trailing spaces from each domain
    return [indicator.strip() for indicator in related_indicators]


def associate_indicator_to_incident() -> CommandResults:
    human_readable_str = "No indicator to associate."

    is_associated = demisto.context().get("associatedIndicators") or False
    if is_associated:
        human_readable_str = "Related indicators are already associated."
    else:
        incident_obj = demisto.incident()
        incident_id = incident_obj["id"]
        related_indicators = get_related_indicators(
            incident_obj.get("CustomFields", {}).get("additionalindicators") or '')
        related_indicators_count = len(related_indicators)
        if related_indicators_count > 0:
            demisto.info(
                f"Associating {related_indicators_count} Indicators to Incident {incident_id}: {related_indicators}")
            associated_indicators = {
                "incidentId": incident_id, "indicatorsValues": ",".join(related_indicators)}

            demisto.executeCommand(
                "associateIndicatorsToIncident", associated_indicators)

            human_readable_str = f"Associated {related_indicators_count} Indicators to Incident {incident_id}"
            # set context if already associated the indicators
            appendContext("associatedIndicators", True, dedup=True)

    return CommandResults(readable_output=human_readable_str)


def main():
    try:
        return_results(associate_indicator_to_incident())
    except Exception as ex:
        return_error(
            f"Failed to execute AssociateIndicatorsToIncident. Error: {str(ex)}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
