import base64
import os

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *


def read_file(args):
    max_file_size = demisto.get(args, "maxFileSize")
    if max_file_size:
        max_file_size = int(max_file_size)
    else:
        max_file_size = 1024**2

    entry_id = args.get("entryID")
    input_encoding = args.get("input_encoding", "utf-8")
    output_data_type = args.get("output_data_type", "raw")
    output_metadata = argToBoolean(args.get("output_metadata", "false"))

    file_path = execute_command("getFilePath", {"id": entry_id})["path"]
    file_size = os.path.getsize(file_path)

    try:
        # always reading in bytes mode
        with open(file_path, "rb") as f:
            raw = f.read(max_file_size)
            eof = len(f.read(1)) == 0
    except Exception as e:
        raise DemistoException(f"There was a problem opening or reading the file.\nError is: {e}")

    if not output_metadata and len(raw) == 0:
        raise DemistoException("No data could be read.")

    message = f"Read {len(raw)} bytes from file"

    # then decoding the raw data
    if input_encoding == "binary":
        data = raw
    else:
        try:
            data = raw.decode(input_encoding)  # type: ignore[assignment]
        except UnicodeDecodeError as e:
            # ---- extract bad bytes ----
            bad_bytes = raw[e.start : e.end]
            bad_hex = bad_bytes.hex()
            bad_repr = repr(bad_bytes)

            demisto.info(
                f"Warning: failed to decode bytes at positions {e.start}-{e.end} using encoding '{input_encoding}'."
                f" Bytes (hex)={bad_hex}, repr={bad_repr} for file: {file_path}"
            )

            data = raw.decode(input_encoding, errors="replace")  # type: ignore[assignment]

    # output handling
    if output_data_type == "raw":
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")  # type: ignore[assignment]

    elif output_data_type == "base64":
        if isinstance(data, str):
            data = data.encode(input_encoding or "utf-8")
        data = base64.b64encode(data).decode()  # type: ignore[assignment]

    elif output_data_type == "json":
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")  # type: ignore[assignment]
        data = json.loads(data)

    else:
        raise DemistoException(f"Invalid data encoding name: {output_data_type}")

    if output_metadata:
        return_results(
            CommandResults(
                outputs_prefix="ReadFile(obj.EntryID===val.EntryID)",
                outputs={"Data": data, "EntryID": entry_id, "FileSize": file_size, "EOF": eof},
                readable_output=message + ":\n" + str(data),
            )
        )
    else:
        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["text"],
                "Contents": {"FileData": data},
                "HumanReadable": message + ":\n" + str(data),
                "EntryContext": {"FileData": data},
            }
        )


def main():
    try:
        read_file(demisto.args())
    except Exception as e:
        return_error(f"Failed to run script - {e}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
