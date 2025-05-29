import traceback

import demistomock as demisto
from CommonServerPython import *


def get_html_representation(entity: str, is_isolated: str) -> str:
    if not entity:
        html = "<div style='color:grey; text-align:center;'><h1>No IP Address associated with the ChronicleAsset</h1></div>"
    else:
        html = f"<div style='color:green; text-align:center;'><h1>{entity}<br/>IP Address Not Isolated</h1></div>"
        if is_isolated == "Yes":
            html = f"<div style='color:red; text-align:center;'><h1>{entity}<br/>IP Address Isolated</h1></div>"
    return html


def main() -> None:
    try:
        indicator_custom_fields = demisto.args().get("indicator").get("CustomFields", {})
        entity = indicator_custom_fields.get("chronicleassetip", "")
        is_isolated = indicator_custom_fields.get("chronicleisolatedip", "No")
        html = get_html_representation(entity, is_isolated)

        demisto.results({"Type": 1, "ContentsFormat": formats["html"], "Contents": html})

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Could not load widget:\n{e}")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
