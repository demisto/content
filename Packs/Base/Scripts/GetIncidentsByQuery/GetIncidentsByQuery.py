from CommonServerPython import *

import pickle
import uuid

from GetIncidentsApiModule import *


def encode_outputs(incidents: list[dict], output_format: str) -> str | bytes:
    match output_format:
        case "pickle":
            return pickle.dumps(incidents, protocol=2)  # guardrails-disable-line
        case "json":
            return json.dumps(incidents)
        case _:
            raise DemistoException(f"Invalid output format: {output_format}")


def to_file_entry(incidents: list[dict], output_format: str) -> dict[str, Any]:
    file_name = str(uuid.uuid4())
    encoded_data = encode_outputs(incidents, output_format)
    return fileResult(file_name, encoded_data) | {
        "Contents": incidents,
        "HumanReadable": f"Fetched {len(incidents)} incidents successfully",
        "EntryContext": {
            "GetIncidentsByQuery": {
                "Filename": file_name,
                "FileFormat": output_format,
            },
        }
    }


def main():
    try:
        args = demisto.args()
        incidents = get_incidents_by_query(args)
        return_results(to_file_entry(incidents, args["outputFormat"]))
    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
