import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import json
from datetime import datetime


def main() -> None:
    integrationInstance = demisto.integrationInstance()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if demisto.command() == 'test-module':
            return_results("ok")

        elif demisto.command() == 'fetch-incidents':
            data = json.loads(demisto.params().get('JSON'))
            incident_name = demisto.params().get("name")
            if not incident_name:
                incident_name = f"Sample Incident - {integrationInstance}"

            incidents = []

            if isinstance(data, list):
                for i in data:
                    incident = {
                        'name': incident_name,
                        'details': json.dumps(i),
                        'occurred': datetime.now().isoformat().split("Z", 1)[0] + "Z",
                        'rawJSON': json.dumps(i)
                    }
                    incidents.append(incident)
            else:
                incident = {
                    'name': incident_name,
                    'details': json.dumps(data),
                    'occurred': datetime.now().isoformat().split("Z", 1)[0] + "Z",
                    'rawJSON': json.dumps(data)
                }
                incidents.append(incident)

            demisto.incidents(incidents)

        elif demisto.command() == 'json-sample-incident-generator-command':
            key = demisto.args().get("key", None)
            value = demisto.args().get("value", None)

            data = json.loads(demisto.params()["JSON"])

            if key and value:
                if "," in key:
                    keys = key.split(",")
                    values = value.split(",")
                    for index, tmp_key in enumerate(keys):
                        data[tmp_key] = values[index]
                else:
                    data[key] = value

            command_results = CommandResults(
                outputs_prefix='JSON.Sample',
                outputs=data
            )
            return_results(command_results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
