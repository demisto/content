import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.debug("pack name = Anything LLM, pack version = 2.0.0")


def main():
    try:
        args = demisto.args()
        gridfield = args.get("documentsfield", "")
        if gridfield == "":
            raise Exception("The documentsfield name parameter was not provided")
        documents = execute_command("anyllm-document-list", {})
        docs: list = []
        items = documents["localFiles"]["items"][0]["items"]

        for d in items or []:
            link = ""
            if d["chunkSource"].startswith("link://https:"):
                link = d["chunkSource"].replace("link://", "")
            gridrow = {
                "action": " ",
                "author": d["docAuthor"],
                "title": d["title"],
                "description": d["description"],
                "source": d["docSource"],
                "link": link,
            }
            docs.append(gridrow)

        rows = json.dumps({gridfield: docs})
        execute_command("setIncident", {"customFields": rows, "version": -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmDocuments: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
