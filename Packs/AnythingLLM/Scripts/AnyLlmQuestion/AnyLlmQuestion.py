import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from datetime import datetime
import uuid


def main():
    try:
        args = demisto.args()
        question = args.get("question", "")
        mode = args.get("mode", "")
        if mode == "" or question == "":
            raise Exception("The question or mode parameters were not provided")
        inci = demisto.incident()["CustomFields"]
        workspace = inci["anythingllmworkspace"]
        context = inci.get("anythingllmnewcontext", "")
        t = inci.get("anythingllmcurthread", "")
        if t == "":
            threads = {}
        else:
            threads = json.loads(t)
        thread = threads.get(workspace, "")
        if thread == "":
            thread_uuid = str(uuid.uuid4())
            threads[workspace] = thread_uuid
            execute_command("anyllm-workspace-thread-new", {"workspace": workspace, "thread": thread_uuid})
            execute_command("setIncident", {"customFields": {"anythingllmcurthread": json.dumps(threads)}})
        else:
            thread_uuid = threads[workspace]
        now = datetime.now().strftime("%Y %B %d %I:%M%p")
        results = execute_command(
            "anyllm-workspace-thread-chat",
            {"message": f"{context}\n{question}", "mode": mode, "workspace": inci["anythingllmworkspace"], "thread": thread_uuid},
        )
        convo = f"{inci.get('anythingllmconversation', '')} \n\n##### {now} [{mode}]: {question}\n\n{results['textResponse']}\n"
        convo += "\n**Embedded Chunks Used**\n"

        for s in results["sources"]:
            convo += f"* {s['score']:0.2f},  {s['title']}\n"

        execute_command("setIncident", {"customFields": {"anythingllmconversation": convo, "anythingllmnewcontext": ""}})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"AnyLlmQuestion: error is - {ex}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
