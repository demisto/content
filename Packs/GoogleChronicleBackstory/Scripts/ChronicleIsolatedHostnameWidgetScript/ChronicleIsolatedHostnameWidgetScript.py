import demistomock as demisto
from CommonServerPython import *

import traceback


def get_html_representation(entity: str, is_isolated: str) -> str:
    if not entity:
        html = "<div style='color:grey; text-align:center;'><h1>No Hostname associated with the " \
               "ChronicleAsset</h1></div>"
    else:
        html = "<div style='color:green; text-align:center;'><h1>{0}<br/>Hostname Not Isolated</h1></div>"\
            .format(entity)
        if is_isolated == 'Yes':
            html = "<div style='color:red; text-align:center;'><h1>{0}<br/>Hostname Isolated</h1></div>"\
                .format(entity)
    return html


def main() -> None:
    try:
        indicator_custom_fields = demisto.args().get('indicator').get('CustomFields', {})
        entity = indicator_custom_fields.get('chronicleassethostname', '')
        is_isolated = indicator_custom_fields.get('chronicleisolatedhostname', 'No')
        html = get_html_representation(entity, is_isolated)

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
