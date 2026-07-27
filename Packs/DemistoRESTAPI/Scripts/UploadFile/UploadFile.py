import time
from CommonServerPython import *

# Retry configuration for transient upload failures.
MAX_RETRIES = 3  # number of retries after the initial attempt
BASE_BACKOFF = 2  # seconds for the first backoff; doubles each retry (2s -> 4s -> 8s)
MAX_BACKOFF = 30  # cap on a single backoff interval, in seconds

# Substrings (lower-cased) that identify a transient error worth retrying.
TRANSIENT_ERROR_MARKERS = (
    "502",
    "under maintenance",
    "connection reset by peer",
    "context deadline exceeded",
    "client.timeout",
)


def is_transient_error(entry: Any) -> bool:
    """Return True if the given entry is an error caused by a transient server condition.

    Only errors whose contents match one of the known transient markers are considered
    retryable. Any other error (e.g. bad incident id, permission error) is permanent and
    must fail fast.
    """
    if not is_error(entry):
        return False
    contents = str(entry.get("Contents", "")).lower()
    return any(marker in contents for marker in TRANSIENT_ERROR_MARKERS)


def upload_file(incident_id: str, entry_id: str, body: str = "", using: str = "", as_incident_attachment: bool = True):
    """Upload a file via core-api-multipart, retrying transient failures with exponential backoff.

    On a transient error the call is retried up to MAX_RETRIES times with a doubling backoff.
    Permanent errors are returned immediately. On exhausting all retries the last response is returned.
    """
    service_name = "incident" if as_incident_attachment else "entry"
    args = {"uri": f"{service_name}/upload/{incident_id}", "entryID": entry_id, "body": body, "using": using}

    response = demisto.executeCommand("core-api-multipart", args)
    for attempt in range(MAX_RETRIES):
        entry = response[0]
        if not is_transient_error(entry):
            # Success, or a permanent error - do not retry.
            return response

        delay = min(BASE_BACKOFF * 2**attempt, MAX_BACKOFF)
        demisto.debug(
            f"UploadFile: transient error uploading entry {entry_id} to incident {incident_id} "
            f"(attempt {attempt + 1}/{MAX_RETRIES + 1}). Retrying in {delay} seconds. "
            f"Error: {entry.get('Contents')}"
        )
        time.sleep(delay)  # pylint: disable=E9003
        response = demisto.executeCommand("core-api-multipart", args)

    return response


def upload_file_command(args: dict) -> list[CommandResults]:
    command_results: list[CommandResults] = []
    incident_id = args.get("incID", "")
    entry_ids = argToList(args.get("entryID", ""))
    body = args.get("body", "")
    target = args.get("target", "war room entry")
    using = args.get("using", "")
    for entry_id in entry_ids:
        response = upload_file(incident_id, entry_id, body, using, "attachment" in target)
        if is_error(response[0]):
            raise DemistoException(f"There was an issue uploading the file. Error received: {response[0]['Contents']}")

        uploaded_entry_id = demisto.dt(response, "Contents.response.entries.id")
        readable = "File uploaded successfully."
        # in case the file uploaded as war room entry
        if uploaded_entry_id:
            readable += f" Entry ID is {uploaded_entry_id}"
        if body:
            readable += f". Comment is:{body}"
        command_results.append(CommandResults(readable_output=readable, raw_response=response))
    return command_results


def main():
    try:
        return_results(upload_file_command(demisto.args()))
    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
