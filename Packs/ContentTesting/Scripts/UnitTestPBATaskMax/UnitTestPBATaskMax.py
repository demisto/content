import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


BLUE1 = "rgb(138, 160, 171)"
BLUE2 = "rgb(109, 150, 171)"
BLUE3 = "rgb(79, 140, 171)"
BLUE4 = "rgb(49, 131, 171)"
BLUE5 = "rgb(21, 122, 171)"
BLUE6 = "rgb(2, 112, 171)"
COLORS = [BLUE1, BLUE2, BLUE3, BLUE4, BLUE5, BLUE6]

FORMATS = ["bar", "pie"]
LAYOUTS = ["horizontal", "vertical"]

STATFIELD = 'maxdur'


def NewWidgetStat(name: str, color: str, label: str, data: list) -> dict:
    wstat = {'name': name, 'color': color, 'data': [data], 'label': label, 'groups': []}
    return wstat


def NewWidget(formatt: str, layout: str, wstat: list) -> dict:
    if formatt in FORMATS and layout in LAYOUTS:
        widget = {'Type': 17, 'ContentsFormat': formatt, 'Contents': {'stats': wstat, 'params': {'layout': layout}}}
    else:
        widget = {}
        demisto.debug(f"{format=} and {layout=} don't match any condition. {widget=}")
    return widget


def main():
    try:
        ctx = demisto.context()
        if 'PlaybookStatistics' not in ctx:
            return
        stats = json.loads(ctx['PlaybookStatistics'])
        if len(stats) == 0:
            return
        wstats: list = []
        length = len(COLORS)
        i = length
        for _key, val in stats.items():
            if val[STATFIELD] == 0:
                continue
            newstat = NewWidgetStat("", COLORS[i % length], val['name'], val[STATFIELD])
            wstats.append(newstat)
            i += 1

        widget = NewWidget("pie", "vertical", wstats)
        demisto.results(widget)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"UnitTestPBATaskAvg: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
