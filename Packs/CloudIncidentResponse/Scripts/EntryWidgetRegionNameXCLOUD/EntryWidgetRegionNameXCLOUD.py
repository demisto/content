<<<<<<< HEAD
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BLACK_HTML_STYLE = "color:#555555;text-align:center;font-size:200%;"


def main():
    try:
        alert = demisto.context().get('Core', {}).get('OriginalAlert')[0]
=======
import demistomock as demisto  # noqa: F401   # pragma: no cover
from CommonServerPython import *  # noqa: F401   # pragma: no cover

BLACK_HTML_STYLE = "color:#555555;text-align:center;font-size:200%;"  # pragma: no cover


def main():  # pragma: no cover
    try:
        alert = demisto.context().get('Core', {}).get('OriginalAlert')
        if isinstance(alert, list):
            alert = alert[0]
>>>>>>> master
        event = alert.get('event')
        regionName = event.get('region')

        html = f"<h1 style='{BLACK_HTML_STYLE}'>{str(regionName)}</h1>"

        return return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html,
        })
    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


<<<<<<< HEAD
if __name__ in ["__main__", "builtin", "builtins"]:
    return_results(main())
=======
if __name__ in ["__main__", "builtin", "builtins"]:  # pragma: no cover
    return_results(main())  # pragma: no cover
>>>>>>> master
