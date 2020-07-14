from typing import Tuple

from CommonServerPython import *


# res = executeCommand("demisto-api-multipart",
#                      {"uri": 'entry/upload/' + args.incidentID, "entryID": args.entryID, "body": args.body});
# if (isError(res[0])) {
# return res;
# }
# var
# entryId = dq(res, 'Contents.response.entries.id');
#
# var
# md = 'File uploaded successfully. Entry ID is ' + entryId;
# if (args.body)
# {
# md += '. Comment is:' + args.body;
# }
#
# return {
#     ContentsFormat: formats.json,
#     Type: entryTypes.note,
#     Contents: res,
#     HumanReadable: md
# };

# args = demisto.args()
# incident_id = args.get('incident_id')
# entry_id = args.get('entryID')
# body = args.get('body', None)
#
# response = demisto.executeCommand("demisto-api-multipart",
#                                   {"uri": "incident/upload/{}".format(incident_id), "entryID": entry_id, "body": body})[
#     0]
# if isError(response):
#     demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
#                      "Contents": "There was an issue uploading file.  Check API key and input arguments."})
# else:
#     if body:
#         demisto.results("Successfully uploaded file to incident. Comment is:" + body)
#     else:
#         demisto.results("Successfully uploaded file to incident")


def upload_file(incident_id: str, entry_id: str, body: str = ''):
    return demisto.executeCommand("demisto-api-multipart",
                                  {"uri": f'entry/upload/{incident_id}', "entryID": entry_id, "body": body})


def upload_file_command(args: dict) -> Tuple[str, str]:
    incident_id = args.get('incidentID')
    entry_id = args.get('entryID')
    body = args.get('body')

    response = upload_file(incident_id, entry_id, body)
    if isError(response[0]):
        raise Exception("There was an issue uploading the file. Check your API key and input arguments.")

    uploaded_entry_id = demisto.dt(response, 'Contents.response.entries.id')
    readable = f'File uploaded successfully. Entry ID is {uploaded_entry_id}'
    if body:
        readable += f'. Comment is:{body}'

    return readable, response


def main():
    try:
        readable, response = upload_file_command(demisto.args())
        return_outputs(readable, {}, response)
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
