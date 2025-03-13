import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

demisto.debug("pack name = Anything LLM, pack version = 2.0.0")


def main():
    try:
        args = demisto.args()
        workspace = args.get("workspace", "")
        gridfield = args.get("embeddingfield", "")
        if workspace == "" or gridfield == "":
            raise Exception("The workspace or gridfield parameter was not provided")
        wrk = execute_command("anyllm-workspace-get", {"workspace": workspace})
        embedds: list = []

        for embed in wrk["workspace"][0]["documents"]:
            gridrow = {"action": "", "title": json.loads(embed["metadata"])["title"], "pinned": embed["pinned"]}
            embedds.append(gridrow)

        rows = json.dumps({gridfield: embedds})
        execute_command("setIncident", {"customFields": rows, "version": -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmWorkspaceEmbeddings: error - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
