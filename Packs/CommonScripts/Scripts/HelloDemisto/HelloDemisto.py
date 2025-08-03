from CommonServerPython import *  # noqa: F401


if __name__ in ("__main__", "__builtin__", "builtins"):
    name = demisto.args().get('name') or "NoBody"
    name = name.strip() if name else 'Demisto'
    demisto.results(f'Hello, {name}!')
