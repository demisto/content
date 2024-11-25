import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        llmupload = demisto.incident()['CustomFields'].get("llmupload", "").strip()
        if llmupload == "":
            raise Exception(f"No processed document found in [llmupload] incident field ready for upload")

        args = json.loads(llmupload)
        title = args.get("title", "")
        files = demisto.context().get("File", "")
        if files == "":
            raise Exception(f"No File key found in context for document title [{title}]")

        if isinstance(files, dict):
            files = [files]

        for ff in files:
            if ff['Name'] == title:
                args['title'] = f"{ff['EntryID']}_{title}"
                execute_command("anyllm-document-upload-text", args)
                execute_command("setIncident", {'customFields': {'llmupload': ""}, 'version': -1})
                # execute_command("AnyLlmDocuments", {'documentsfield': "llmdocuments"})
                return

        raise Exception(f"Processed document {title} not found in File context key")
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmUploadDocument: error is - {str(ex)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
