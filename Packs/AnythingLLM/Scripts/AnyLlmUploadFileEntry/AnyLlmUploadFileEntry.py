import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import shutil


def main():
    try:
        name = demisto.args().get("name", "")
        if name == "":
            raise Exception("The name parameter for the war room file entry was not provided")

        args = {'title': name, 'description': "", 'author': "", 'source': ""}
        files = demisto.context().get("File", "")
        if files == "":
            raise Exception("No File key found in context for war room file entries")
        if isinstance(files, dict):
            files = [files]

        for file in files:
            title = args['title']
            if file['Name'] == title:
                entry_id = file['EntryID']
                break

        file_path = demisto.getFilePath(entry_id)['path']
        file_name = demisto.getFilePath(entry_id)['name']
        shutil.copy(file_path, file_name)
        f = open(file_name, 'rb')
        text = f.read().decode("utf-8")
        f.close()
        shutil.rmtree(file_name, ignore_errors=True)
        args['text'] = text

        execute_command("setIncident", {'customFields': {'anythingllmupload': json.dumps(args)}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmUploadFileEntry: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
