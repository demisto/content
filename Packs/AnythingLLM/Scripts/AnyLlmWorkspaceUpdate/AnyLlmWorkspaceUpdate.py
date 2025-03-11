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


def UpdateConversation(workspace: str):
    inci = demisto.incident()["CustomFields"]
    t = inci.get("anythingllmcurthread", "")
    threads = {}
    if t != "":
        threads = json.loads(t)
    thread = threads.get(workspace, "")

    if thread != "":
        response = execute_command(
            "anyllm-workspace-thread-chats", {"workspace": workspace, "thread": thread}, extract_contents=True
        )
        convo = ""
        for h in response.get("history", []):
            if h["role"] == "user":
                tm = datetime.fromtimestamp(h["sentAt"]).strftime("%Y %B %d %I:%M%p")
                content = h["content"].replace("\n", "")
                convo += f"##### {tm} |||MODE||| {content}\n"
            else:
                convo = convo.replace("|||MODE|||", f"[{h['type']}]:")
                convo += h["content"] + "\n"
                convo += "\n**Embedded Chunks Used**\n"
                for s in h["sources"]:
                    convo += f"* {s['score']:0.2f},  {s['title']}\n"
        execute_command("setIncident", {"customFields": {"anythingllmconversation": convo}})
    else:
        execute_command("setIncident", {"customFields": {"anythingllmconversation": ""}})


def main():
    try:
        args = demisto.args()
        oldgrid = json.loads(args.get("old", ""))
        newgrid = json.loads(args.get("new", ""))
        if len(oldgrid) == 0 or len(newgrid) == 0:
            return

        workspace = ""

        for old, new in zip(oldgrid, newgrid):
            if "action" in new:
                if new["action"] == "Current" and old["action"] != "Current":
                    workspace = new["name"]
                    execute_command("setIncident", {"customFields": {"anythingllmworkspace": workspace}})
                    break

        index = 0
        updated = False
        for old, new in zip(oldgrid, newgrid):
            if old == new:
                newgrid[index]["action"] = ""
            else:
                workspace = new["name"]
                settings = {
                    "openAiTemp": new["temperature"],  # 0.0 .. 1.0
                    "similarityThreshold": new["similarity"],  # vector DB similarity (0.0, 0.25, 0.50, 0.75)
                    "topN": new["topnresults"],  # top N similar results to return to chat context (1 - 12)
                }
                execute_command("anyllm-workspace-settings", {"workspace": workspace, "settings": settings})
            index += 1
            updated = True

        if workspace != "" and updated:
            grid = json.dumps({"anythingllmworkspacelist": newgrid})
            execute_command("setIncident", {"customFields": grid, "version": -1})
            UpdateEmbeddings(workspace)
            UpdateConversation(workspace)
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmWorkspaceUpdate: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
