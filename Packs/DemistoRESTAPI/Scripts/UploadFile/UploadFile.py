
from CommonServerPython import *


def upload_file(incident_id: str, entry_id: str, body: str = '', as_incident_attachment: bool = True):
    service_name = 'incident' if as_incident_attachment else 'entry'
    return demisto.executeCommand("core-api-multipart",
                                  {"uri": f'{service_name}/upload/{incident_id}', "entryID": entry_id, "body": body})


def upload_file_command(args: dict) -> list[CommandResults]:
    command_results: list[CommandResults] = []
    incident_id = args.get('incID', '')
    entry_ids = argToList(args.get('entryID', ''))
    body = args.get('body', '')
    target = args.get('target', 'war room entry')
    for entry_id in entry_ids:
        response = upload_file(incident_id, entry_id, body, target == 'incident attachment')
        if is_error(response[0]):
            raise DemistoException("There was an issue uploading the file. Check your API key and input arguments.")

        uploaded_entry_id = demisto.dt(response, 'Contents.response.entries.id')
        readable = 'File uploaded successfully.'
        # in case the file uploaded as war room entry
        if uploaded_entry_id:
            readable += f' Entry ID is {uploaded_entry_id}'
        if body:
            readable += f'. Comment is:{body}'
        command_results.append(CommandResults(readable_output=readable, raw_response=response))
    return command_results


def main():
    try:
        return_results(upload_file_command(demisto.args()))
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
