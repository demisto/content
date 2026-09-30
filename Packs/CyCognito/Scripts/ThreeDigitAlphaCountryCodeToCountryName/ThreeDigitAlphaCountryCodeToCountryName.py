import demistomock as demisto  # noqa: F401
import pycountry
from CommonServerPython import *  # noqa: F401


def main():
    try:
        loc_names = demisto.args().get("value", [])
        names = []
        if not loc_names:
            demisto.results("")
        else:
            for location in argToList(loc_names):
                country = pycountry.countries.get(alpha_3=location)
                if country is not None:
                    names.append(country.name)
            demisto.results(names)
    except AttributeError:
        demisto.results("")
    except Exception as e:
        return_error(f"Error occurred while parsing country name:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
