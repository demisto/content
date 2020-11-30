import demistomock as demisto
from CommonServerPython import *

import traceback


def get_html_representation(entity: str, potentially_isolated: str) -> str:
    if not entity:
        html = "<div style='color:grey; text-align:center;'><h1>No IP Address associated with the " \
               "ChronicleAsset</h1></div>"
    else:
        html = "<div style='color:green; text-align:center;'><h1>{0}<br/>IP Address Not Blocked</h1></div>" \
            .format(entity)
        if potentially_isolated == 'Yes':
            html = "<div style='color:orange; text-align:center;'><h1>{0}<br/>IP Address Potentially Blocked</h1>" \
                   "</div>".format(entity)
    return html


def main() -> None:
    try:
        indicator_custom_fields = demisto.args().get('indicator').get('CustomFields', {})
        entity = indicator_custom_fields.get('chronicleassetip', '')
        potentially_isolated = indicator_custom_fields.get('chroniclepotentiallyblockedip', 'No')
        html = get_html_representation(entity, potentially_isolated)

        demisto.results({
            "Type": 1,
            "ContentsFormat": formats["html"],
            "Contents": html
        })

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Could not load widget:\n{e}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
