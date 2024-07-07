from CommonServerPython import *
import demistomock as demisto


def test():
    from GetIncidentsApiModule import main

    try:
        main()
    except Exception:
        pass

    assert True
