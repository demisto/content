import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3

urllib3.disable_warnings()


def shorten_text(text: str) -> str:
    parts = text.split()
    if len(parts) == 2:
        return f"{parts[0]}{parts[1][0].lower()}"
    return text  # Return original if not exactly two words


def search_for_indicator(args: dict) -> Union[CommandResults, list]:
    time_frame: str = args["time_frame"]
    data_set: str = args["data_set"]
    indicator: str = args["indicator"]

    time_frame_for_query: str = shorten_text(time_frame)

    return demisto.executeCommand(command="xdr-xql-generic-query",
                                  args={"query": f"config timeframe = {time_frame_for_query} |"
                                                 f" search {indicator} dataset = {data_set}"})


def main():
    try:
        return search_for_indicator(demisto.args())
    except Exception as e:
        return_error("Error occurred while executing search_for_indicator. Exception info:\n" + str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
