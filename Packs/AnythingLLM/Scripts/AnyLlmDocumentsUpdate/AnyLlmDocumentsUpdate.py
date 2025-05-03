import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def UpdateEmbeddings(workspace: str):
    # Had to duplicate automation since unable to execute_command with it
    wrk = execute_command("anyllm-workspace-get", {"workspace": workspace})
    embedds = []

    for embed in wrk["workspace"][0]["documents"]:
        gridrow = {"action": "", "title": json.loads(embed["metadata"])["title"], "pinned": embed["pinned"]}
        embedds.append(gridrow)

    grid = json.dumps({"anythingllmembeddings": embedds})
    execute_command("setIncident", {"customFields": grid, "version": -1})


def main():
    try:
        args = demisto.args()
        oldgrid = json.loads(args.get("old", ""))
        newgrid = json.loads(args.get("new", ""))
        if len(oldgrid) == 0 or len(newgrid) == 0:
            return

        folder = "custom-documents"
        workspace = demisto.incident()["CustomFields"].get("anythingllmworkspace", "")
        if workspace == "":
            raise Exception("Workspace not defined")

        index = 0
        embeds = False
        for old, new in zip(oldgrid, newgrid):
            if old != new:
                if new["action"] == "Embed":
                    new["action"] = ""
                    newgrid[index] = new
                    execute_command(
                        "anyllm-workspace-add-embedding", {"workspace": workspace, "folder": folder, "document": new["title"]}
                    )
                    embeds = True
                elif new["action"] == "Delete":
                    newgrid.remove(new)
                    execute_command("anyllm-document-delete", {"folder": folder, "document": new["title"]})
            index += 1

        if embeds:
            UpdateEmbeddings(workspace)
        grid = json.dumps({"anythingllmdocuments": newgrid})
        execute_command("setIncident", {"customFields": grid, "version": -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmDocumentsUpdate: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
