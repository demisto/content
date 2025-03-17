import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        cargs = {
            'link': args.get("link", ""),
            'title': args.get("title", ""),
            'author': args.get("author", ""),
            'description': args.get("description", ""),
            'source': args.get("source", "")
        }
        if cargs['title'] == "" or cargs['link'] == "":
            raise Exception("The title or link parameter was not provided")
        execute_command("anyllm-document-upload-link", cargs)
        execute_command("AnyLlmDocuments", {'customFields': {'documentsfield': "anythingllmdocuments"}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmUploadWebLink: error - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
