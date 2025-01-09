import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback


RED = "rgb(204, 57, 24)"
ORANGE = "rgb(201, 176, 48)"
GREEN = "rgb(148, 196, 143)"
GREY = "rgb(197, 197, 197)"
BLUE = "rgb(149, 188, 201)"
FORMATS = ["bar", "pie"]
LAYOUTS = ["horizontal", "vertical"]


def TaskWidget(tstat: dict) -> list:
    group = []

    g1 = {'name': "Completed", 'data': [tstat['completed']], 'color': GREEN}
    group.append(g1)
    g2 = {'name': "Started", 'data': [tstat['started']], 'color': ORANGE}
    group.append(g2)
    g3 = {'name': "Waiting", 'data': [tstat['waiting']], 'color': BLUE}
    group.append(g3)
    g4 = {'name': "NotExecuted", 'data': [tstat['notexecuted']], 'color': GREY}
    group.append(g4)
    g5 = {'name': "Error", 'data': [tstat['error']], 'color': RED}
    group.append(g5)

    return group


def TaskWidgetGroup(wstats: list, name: str, stat: list) -> list:
    w = NewWidgetStatGroup(name, stat)
    wstats.append(w)
    return wstats


def NewWidgetStatGroup(name: str, data: list) -> dict:
    wstat = {'name': name, 'groups': data, 'data': [], 'label': "", 'color': ""}
    return wstat


def NewWidget(format: str, layout: str, wstat: list) -> dict:
    if format in FORMATS and layout in LAYOUTS:
        widget = {'Type': 17, 'ContentsFormat': format, 'Contents': {'stats': wstat, 'params': {'layout': layout}}}
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
        for _key, val in stats.items():
            tw = TaskWidget(val)
            wstats = TaskWidgetGroup(wstats, val['name'], tw)
        widget = NewWidget("bar", "vertical", wstats)
        demisto.results(widget)
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"UnitTestPBAStats: Exception failed to execute. Error: {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
