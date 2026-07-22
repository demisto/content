import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_color(cvss) -> str:
    """
    Gets a CVSS score and sends back the correct hex code for a color as a string.

    Args:
        cvss: A CVE CVSS score.

    Returns:
        str: The color of the score in hex format.
    """

    cvss = float(cvss)

    if cvss >= 7.0:
        color = "#E1211E"
    elif cvss >= 4.0:
        color = "#F47D3E"
    elif cvss > 0.0:
        color = "#F9B637"
    else:
        color = "#CDCED6"

    return color


def main():
    indicator = demisto.callingContext.get("args", {}).get("indicator", {})
    cvss = indicator.get("CustomFields", {}).get("cvssscore", None)

    if cvss is None:
        color = "#CDCED6"
        return_results(CommandResults(readable_output=f"# <-:->{{{{color:{color}}}}}(**N/A**)"))  # noqa: E231
    else:
        color = get_color(cvss)
        return_results(CommandResults(readable_output=f"# <-:->{{{{color:{color}}}}}(**{cvss}**)"))  # noqa: E231


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
