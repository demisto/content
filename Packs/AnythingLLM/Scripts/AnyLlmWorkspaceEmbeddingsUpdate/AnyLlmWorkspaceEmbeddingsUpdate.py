import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        args = demisto.args()
        oldgrid = json.loads(args.get('old', ""))
        if len(oldgrid) == 0:
            return
        newgrid = json.loads(args.get('new', ""))
        folder = 'custom-documents'
        workspace = demisto.incident()["CustomFields"].get("anythingllmworkspace", "")
        if workspace == "":
            raise Exception("Workspace not defined")

        index = 0
        updated = False
        for old, new in zip(oldgrid, newgrid):
            if old != new:
                if new['action'] in ["Pin", "Unpin"]:
                    if new['action'] == "Pin":
                        status = 'true'
                    else:
                        status = 'false'
                    new['pinned'] = status
                    new['action'] = ""
                    newgrid[index] = new
                    execute_command("anyllm-workspace-pin", {
                        'workspace': workspace,
                        'folder': folder,
                        'document': new['title'],
                        'status': status
                    })
                elif new['action'] == "Remove":
                    newgrid.remove(new)
                    execute_command("anyllm-workspace-delete-embedding", {
                        'workspace': workspace,
                        'folder': folder,
                        'document': new['title']
                    })
                updated = True
            index += 1

        if updated:
            grid = json.dumps({'anythingllmembeddings': newgrid})
            execute_command("setIncident", {'customFields': grid, 'version': -1})
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'AnyLlmWorkspaceEmbeddingsUpdate: error is - {ex}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
