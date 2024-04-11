import base64
from pathlib import Path
from typing import Any

import demistomock as demisto
from CommonServerPython import *


def get_data_from_file(entry_id: str) -> bytes:
    """Reads the file associated with the entry_id and returns its data as bytes."""
    try:
        return Path(demisto.getFilePath(entry_id)["path"]).read_bytes()
    except Exception as e:
        raise DemistoException(f'There was a problem opening or reading the file.\nError is: {e}')


def get_entry_metadata(entry_id: str) -> dict:  # pragma: no cover
    res = demisto.executeCommand("getEntry", {"id": entry_id})
    if is_error(res):
        raise DemistoException(get_error(res))
    return res[0]


def get_data_entry(entry_metadata: dict) -> Any:
    """Retrieves the data associated with an entry based on its type."""
    entry_type: int = entry_metadata["Type"]
    match entry_type:
        case (
            EntryType.FILE
            | EntryType.IMAGE
            | EntryType.ENTRY_INFO_FILE
            | EntryType.VIDEO_FILE
        ):
            return get_data_from_file(entry_metadata["ID"])
        case _:
            return entry_metadata["Contents"]


def decode_data(data: Any, data_encoding: str) -> bytes | Any:
    """Given data and its encoding, this function decodes the data according to the provided encoding and returns it."""
    match data_encoding:
        case "base64":
            return base64.b64decode(data)
        case "raw":
            return data
        case _:
            raise ValueError(f'Invalid data encoding value: {data_encoding}, must be either `base64` or `raw`')


def main() -> None:
    args = demisto.args()
    filename = args["filename"]
    data = args.get("data")
    data_encoding = args.get("data_encoding", "raw")
    entry_id = args.get("entryId")

    try:
        if entry_id:
            entry_metadata = get_entry_metadata(entry_id)
            data = get_data_entry(entry_metadata)
        data = decode_data(data, data_encoding)

        return_results(fileResult(filename, data))
    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
