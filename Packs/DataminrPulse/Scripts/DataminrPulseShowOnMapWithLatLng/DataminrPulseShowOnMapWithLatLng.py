import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        coords = demisto.incident().get("CustomFields", {}).get("dataminrpulseeventlocationcoordinates", "")

        if not coords:
            return_results("No coordinates found.")
            return

        if isinstance(coords, str):
            coords = coords.strip("[]").split(",")

        if not isinstance(coords, list) or len(coords) != 2:
            return_results("Invalid coordinates format.")
            return

        lat, lng = float(coords[0].strip()), float(coords[1].strip())

        geo_entry = {
            "Type": EntryType.MAP_ENTRY_TYPE,
            "ContentsFormat": EntryFormat.JSON,
            "Contents": {"lat": lat, "lng": lng},
        }

        return_results(geo_entry)

    except Exception as e:
        return_error(f"Failed to generate geo map entry: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
