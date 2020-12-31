import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime
import json
import uuid
import urllib3

# disable insecure warnings
urllib3.disable_warnings()


def fetch_incidents(num_of_events):
    integration_context = demisto.getIntegrationContext()
    if integration_context.get("done", "false") != "true":
        data = {}
        events = []
        for _ in range(num_of_events):
            events.append({"a": 1, "b": 2})
        data['events'] = events
        demisto.incidents([{
            "name": "incident",
            "rawJSON": json.dumps(data),
            "occurred": datetime.now().isoformat() + 'Z',
        }])
        set_integration_context({"done": "true"})


def main():
    params = demisto.params()
    num_of_events = int(params.get('num_of_events'))

    command = demisto.command()
    try:
        demisto.debug(f"Command being called is {command}")
        if command == "fetch-incidents":
            demisto.incidents(fetch_incidents(num_of_events))
        else:
            raise NotImplementedError(f"Command {command} not implemented.")
    except Exception as e:
        error = f"Error has occurred in the QRadar Integration: {str(e)}"
        LOG(traceback.format_exc())
        if demisto.command() == "fetch-incidents":
            LOG(error)
            LOG.print_log()
            raise Exception(error)
        else:
            return_error(error)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
