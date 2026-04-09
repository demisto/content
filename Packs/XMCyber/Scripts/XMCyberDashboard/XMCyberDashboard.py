import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""XMCyberDashboard Script for Cortex XSOAR
This is a dashboard-widget script built
for the "XM Cyber Dashboard" dashboard.
"""

from typing import Any
import traceback


""" CONSTANTS """

SECURITY_SCORE_RT = "security_score"
COMPROMISING_EXPOSURE_RT = "compromising_exposure"
CRITICAL_ASSETS_RT = "critical_assets"
CHOKE_POINTS_RT = "choke_points"
RETURN_TYPES = [
    SECURITY_SCORE_RT,
    COMPROMISING_EXPOSURE_RT,
    CRITICAL_ASSETS_RT,
    CHOKE_POINTS_RT,
]
SCORE_TO_COLOR = {
    "A": "00ff91",  # Green
    "B": "ffd600",  # Gold
    "C": "ff5f1d",  # Orange
    "D": "ff6691",  # Lollipop
    "F": "99002b",  # Deep Paprika
}


""" COMMAND FUNCTION """


def widget_data_generator(args: Dict[str, Any]) -> str | dict:
    """Generate widget data for XM Cyber Dashboard.

    Args:
        args (Dict[str, Any]): Dictionary containing the function arguments.
            - return_type (str): Type of data to return. Valid values are:
                - "security_score": Returns security score information
                - "choke_points": Returns choke points data
                - "critical_assets": Returns critical assets data
                - "compromising_exposure": Returns compromising exposures data
            Defaults to "security_score" if not provided.

    Returns:
        str | dict:
            - For "security_score": Returns a markdown formatted string
            - For other types: Returns a dictionary with 'total' and 'data' keys

    Raises:
        DemistoException: If return_type is not one of the valid types, or if no
                         XM Cyber CEM integration instance is configured.

    """
    return_type = args.get("return_type", "security_score").strip()

    if return_type not in RETURN_TYPES:
        raise DemistoException(f"Invalid argument provided for 'return_type' with value: '{return_type}'")

    command_results = demisto.executeCommand("xmcyber-get-dashboard-data", {})
    command_output = json.loads(json.dumps(command_results))

    combined_data = {}
    if command_output:
        combined_data = command_output[0].get("Contents", {})
        if not combined_data:
            raise DemistoException("No data found in the response. Please check the 'XM Cyber CEM' integration instance.")
        if not isinstance(combined_data, dict):
            raise DemistoException(
                "Invalid data format in the response. Expected a dictionary, but got "
                f"{type(combined_data)} with value: {combined_data}. Please check the 'XM Cyber CEM' integration instance."
            )
    else:
        raise DemistoException(
            "No XM Cyber CEM integration instance found. Please configure an instance of the 'XM Cyber CEM' integration."
        )

    if return_type == SECURITY_SCORE_RT:
        security_score_response: dict = combined_data.get("SecurityScore", {})
        grade = security_score_response.get("grade", "")
        score = security_score_response.get("score", 0)
        trend = security_score_response.get("trend", 0)
        trend_emoji = "📈" if trend > 0 else ("📉" if trend < 0 else "➡️")
        if trend > 0:
            trend = f"+{trend}"
        return (
            f"## <-:-> Security Score\n\n# <-:-> {{{{color:#{SCORE_TO_COLOR.get(grade, '')}}}}}(**{grade}**)\n\n"
            f"### <-:-> **{score}**\n\n"
            f"#### <-:-> **{trend}** {trend_emoji} From last month"
        )

    if return_type == CHOKE_POINTS_RT:
        choke_points: list = combined_data.get("ChokePoints", [])
        return {
            "total": len(choke_points),
            "data": [
                {
                    "Name": choke_point.get("name", ""),
                    "Severity": choke_point.get("severity", ""),
                    "Severity Score": choke_point.get("severityScore", ""),
                }
                for choke_point in choke_points
            ],
        }

    if return_type == CRITICAL_ASSETS_RT:
        critical_assets: list = combined_data.get("CriticalAssets", [])
        return {
            "total": len(critical_assets),
            "data": [
                {
                    "Name": critical_asset.get("name", ""),
                    "Severity": critical_asset.get("severity", ""),
                    "Severity Score": critical_asset.get("severityScore", ""),
                }
                for critical_asset in critical_assets
            ],
        }

    if return_type == COMPROMISING_EXPOSURE_RT:
        compromising_exposures: list = combined_data.get("CompromisingExposures", [])
        return {
            "total": len(compromising_exposures),
            "data": [
                {
                    "Name": compromising_exposure.get("name", ""),
                    "Complexity": compromising_exposure.get("complexity", ""),
                    "Severity": compromising_exposure.get("severity", ""),
                    "Choke Points": compromising_exposure.get("chokePoints", ""),
                    "Compromised Entities": compromising_exposure.get("entities", ""),
                    "Critical Assets": compromising_exposure.get("criticalAssets", ""),
                    "Critical Assets at Risk": compromising_exposure.get("criticalAssetsAtRisk", ""),
                    "Total Assets": compromising_exposure.get("totalAssets", ""),
                }
                for compromising_exposure in compromising_exposures
            ],
        }

    raise DemistoException(f"Invalid argument provided for 'return_type' with value: '{return_type}'")


""" MAIN FUNCTION """


def main():
    """Main execution function for XMCyberDashboard script.

    Raises:
        Exception: Any exception raised during execution is caught, logged via demisto.error,
                  and returned as an error message via return_error.
    """
    try:
        return_results(widget_data_generator(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to load data using 'XMCyberDashboard' automation script. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
