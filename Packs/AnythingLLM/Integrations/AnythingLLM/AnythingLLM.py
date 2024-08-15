import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import shutil


''' CLIENT CLASS '''
class Client(BaseClient):
    def test_module(self):
        self._http_request("GET", "/v1/auth")


    def document_list(self):
        return self._list("documents")


    def document_get(self, folder: str, document: str):
        try:
            name = document_name(folder, document, self.document_list())
            response = self._http_request(
                method = "GET",
                url_suffix = f"/v1/document/{name}"
            )
        except Exception as e:
            msg = f"AnythingLLM: document_get: exception getting document details - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def document_delete(self, folder: str, document: str):
        try:
            name = document_name(folder, document, self.document_list())
            data = {
                "names": [
                    f"{folder}/{name}"
                ]
            }
            response = self._http_request(
                method = "DELETE",
                url_suffix = "/v1/system/remove-documents",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: document_delete: exception deleting document - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return {"message": response}


    def document_createfolder(self, folder: str):
        try:
            data = {
                "name": folder
            }
            response = self._http_request(
                method = "POST",
                url_suffix = "/v1/document/create-folder",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: document_createfolder: exception creating folder - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def document_move(self, srcfolder: str, dstfolder: str, document: str):
        try:
            name = document_name(srcfolder, document, self.document_list())
            data = {
                "files": [
                    {
                    "from": f"{srcfolder}/{name}",
                    "to": f"{dstfolder}/{name}"
                    }
                ]
            }
            response = self._http_request(
                method = "POST",
                url_suffix = "/v1/document/move-files",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: document_move: exception moving document - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def document_upload_text(self, text: str, title: str, description: str, author: str, source: str):
        try:
            try:
                exists = False
                document_name("custom-documents", title, self.document_list())
                exists = True
            except Exception:
                data = {
                    "textContent": text,
                    "metadata": {
                        "title": title,
                        "docAuthor": author,
                        "description": description,
                        "docSource": source
                    }
                }
                response = self._http_request(
                    method = "POST",
                    url_suffix = "/v1/document/raw-text",
                    json_data = data
                )
            finally:
                if exists:  # pylint: disable=E0601
                    raise Exception(f"document already exists [{title}]")
        except Exception as e:
            msg = f"AnythingLLM: document_upload_text: exception uploading text - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response  # pylint: disable=E0601


    def document_upload_link(self, link: str, title: str, description: str, author: str, source: str):
        try:
            try:
                exists = False
                document_name("custom-documents", title, self.document_list())
                exists = True
            except Exception:
                data = {
                    "link": link,
                    "metadata": {
                        "title": title,
                        "docAuthor": author,
                        "description": description,
                        "docSource": source
                    }
                }
                response = self._http_request(
                    method = "POST",
                    url_suffix = "/v1/document/raw-text",
                    json_data = data
                )
            finally:
                if exists:  # pylint: disable=E0601
                    raise Exception(f"document already exists [{title}]")
        except Exception as e:
            msg = f"AnythingLLM: document_upload_link: exception uploading link [{link}] - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response  # pylint: disable=E0601


    def document_upload_file(self, entry_id):
        try:
            headers = self._headers
            del headers['Content-Type']
            file_path = demisto.getFilePath(entry_id)['path']
            file_name = demisto.getFilePath(entry_id)['name']
            try:
                exists = False
                document_name("custom-documents", file_name, self.document_list())
                exists = True
            except Exception:
                shutil.copy(file_path, file_name)
                response = self._http_request(
                    method = 'POST',
                    headers = headers,
                    url_suffix = "/v1/document/upload",
                    files = {'file': (file_name, open(file_name, 'rb'))}
                )
            finally:
                if exists:  # pylint: disable=E0601
                    raise Exception(f"document already exists [{file_name}]")
        except Exception as e:
            msg = f"AnythingLLM: document_upload_file: exception uploading a file entry [{entry_id}] from the war room - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)
        finally:
            shutil.rmtree(file_name, ignore_errors=True)

        return response  # pylint: disable=E0601


    def workspace_new(self, workspace: str):
        try:
            if len(workspace.strip()) == 0:
                raise Exception("workspace parameter is blank")
            try:
                exists = False
                workspace_slug(workspace, self.workspace_list())
                exists = True
            except Exception:
                data = {
                    'name': workspace
                }
                response = self._http_request(
                    method = "POST",
                    url_suffix = "/v1/workspace/new",
                    json_data = data
                )
                return response
            finally:
                if exists:  # pylint: disable=E0601
                    raise Exception("workspace already exists")
        except Exception as e:
            msg = f"AnythingLLM: workspace_new: exception creating a new workspace [{workspace}] - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)


    def workspace_chat(self, workspace: str, message: str, mode: str):
        return self._chat(workspace, message, mode, "chat")


    def workspace_stream_chat(self, workspace: str, message: str, mode: str):
        return self._chat(workspace, message, mode, "stream-chat")


    def workspace_list(self):
        return self._list("workspaces")


    def workspace_get(self, workspace:str ):
        try:
            slug = workspace_slug(workspace, self.workspace_list())
            response = self._http_request(
                method = "GET",
                url_suffix = f"/v1/workspace/{slug}",
            )
        except Exception as e:
            msg = f"AnythingLLM: workspace_get: exception getting workspace details - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def workspace_delete(self, workspace:str ):
        try:
            slug = workspace_slug(workspace, self.workspace_list())
            self._http_request(
                method = "DELETE",
                url_suffix = f"/v1/workspace/{slug}",
                resp_type='bytes'
            )
        except Exception as e:
            msg = f"AnythingLLM: workspace_delete: exception deleting workspace - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return {"message": {"success": True, "message": "Workspace removed successfully"}}


    def workspace_settings(self, workspace:str, settings: dict ):
        try:
            settings = validate_workspace_settings(settings)
            slug = workspace_slug(workspace, self.workspace_list())
            response = self._http_request(
                method = "POST",
                url_suffix = f"/v1/workspace/{slug}/update",
                json_data = settings
            )
        except Exception as e:
            msg = f"AnythingLLM: workspace_settings: exception updating workspace settings - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def workspace_add_embedding(self, workspace: str, folder: str, document: str):
        return self._embedding(workspace, folder, document, "adds")


    def workspace_delete_embedding(self, workspace: str, folder: str, document: str):
        return self._embedding(workspace, folder, document, "deletes")


    def workspace_pin(self, workspace:str, folder:str, document:str, status: str):
        try:
            if status.lower() == "true":
                pinst = True
            elif status.lower() == "false":
                pinst = False
            else:
                raise Exception("document pin status of [true] or [false] not passed")
            name = document_name(folder, document, self.document_list())
            data = {
                "docPath": f"{folder}/{name}",
                "pinStatus": pinst
            }
            slug = workspace_slug(workspace, self.workspace_list())
            response = self._http_request(
                method = "POST",
                url_suffix = f"/v1/workspace/{slug}/update-pin",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: workspace_pin: exception pinning embedded document to workspace - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def _chat(self, workspace: str, message: str, mode: str, type: str):
        try:
            data = {
                'message': message,
                'mode': validate_chat_mode(mode)
            }
            slug = workspace_slug(workspace, self.workspace_list())
            response = self._http_request(
                method = "POST",
                url_suffix = f"/v1/workspace/{slug}/{type}",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: _chat: exception chatting - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def _list(self, items: str):
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/v1/{items}",
            )
        except Exception as e:
            msg = f"AnythingLLM: _list: exception listing {items} - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response


    def _embedding(self, workspace: str, folder: str, document: str, action: str):
        try:
            name = document_name(folder, document, self.document_list())

            try:
                ws = self.workspace_get(workspace)
            except Exception:
                raise Exception(f"workspace [{workspace}] not found")

            if action == "adds":
                if embedding_exists(name, ws):
                    raise Exception(f"[{document}] already embedded")
            elif action == "deletes":
                if not embedding_exists(name, ws):
                    raise Exception(f"[{document}] not embedded")

            data = {
                action: [f"{folder}/{name}"]
            }
            slug = workspace_slug(workspace, self.workspace_list())
            response = self._http_request(
                method = "POST",
                url_suffix = f"/v1/workspace/{slug}/update-embeddings",
                json_data = data
            )
        except Exception as e:
            msg = f"AnythingLLM: _embedding: exception [{action}] a document embedding - {str(e)}"
            demisto.debug(msg)
            raise Exception(msg)

        return response

''' HELPER FUNCTIONS '''

def embedding_exists(docname: str, ws: dict) -> bool:
    for doc in ws['workspace']['documents']:
        if doc['filename'] == docname:
            return True
    return False


def workspace_slug(workspace: str, workspaces) -> str:
    for w in workspaces['workspaces']:
        if w['name'] == workspace:
            return w['slug']
    raise Exception(f"workspace name not found [{workspace}]")


def normal_document_title(title: str):
    title = ' '.join(title.strip().split())
    return title.lower().replace(" ", "-") + ".txt"


def document_name(folder: str, title: str, documents) -> str:
    for f in documents['localFiles']['items']:
        if f['name'] == folder:
            for d in f['items']:
                if d['title'] in [title, normal_document_title(title)]:
                    return d['name']
    raise Exception(f"document title not found [{title}]")


def validate_chat_mode(mode: str):
    if mode not in ['chat', 'query']:
        raise Exception(f"Invalid chat mode [{mode}]")
    return mode


def validate_workspace_settings(settings: dict):
    new_settings = {}
    if "name" in settings:
        new_settings['name'] = settings['name']
    #if "vectorTag" in settings:
    #    new_settings['vectorTag'] = settings['vectorTag']
    if "openAiTemp" in settings:
        new_settings['openAiTemp'] = float(settings['openAiTemp'])
    if "openAiHistory" in settings:
        new_settings['openAiHistory'] = int(settings['openAiHistory'])
    if "openAiPrompt" in settings:
        new_settings['openAiPrompt'] = settings['openAiPrompt']
    if "similarityThreshold" in settings:
        new_settings['similarityThreshold'] = float(settings['similarityThreshold'])
    #if "chatProvider" in settings:
    #    new_settings['chatProvider'] = settings['chatProvider']
    #if "chatModel" in settings:
    #    new_settings['chatModel'] = settings['chatModel']
    if "topN" in settings:
        new_settings['topN'] = int(settings['topN'])
    if "chatMode" in settings:
        new_settings['chatMode'] = settings['chatMode']
    if "queryRefusalResponse" in settings:
        new_settings['queryRefusalResponse'] = settings['queryRefusalResponse']
    return new_settings


def DictMarkdown(nested, indent):
    md = ""
    if indent == "":
        indent = "-"
    else:
        indent = "  "+indent
    if isinstance(nested, dict):
        for key, val in nested.items():
            if isinstance(val, dict):
                md += f"{indent} {key}\n"
                md += DictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {key}\n"
                md += DictMarkdown(val, indent)
            else:
                md += f"{indent} {key}: {val}\n"
    elif isinstance(nested, list):
        for val in nested:
            md += f"{indent} []\n"
            if isinstance(val, dict):
                md += DictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {val}\n"
                md += DictMarkdown(val, indent)
            else:
                md += f"  {indent} {val}\n"

    return md


''' COMMAND FUNCTIONS '''


def test_module(client: Client, args: dict) -> str:
    try:
        client.test_module()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: ensure API Key is correctly set'
        else:
            raise e

    return 'ok'


def list_command(client: Client, args: dict) -> CommandResults:
    response: dict = {}
    return CommandResults(
        outputs_prefix = 'AnythingLLM.list',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def settings_command(client: Client, args: dict) -> CommandResults:
    response: dict = {}
    return CommandResults(
        outputs_prefix = 'AnythingLLM.settings',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_list_command(client: Client, args: dict) -> CommandResults:
    response = client.document_list()
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_list',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_createfolder_command(client: Client, args: dict) -> CommandResults:
    response = client.document_createfolder(args['folder'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.document_createfolder',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_delete_command(client: Client, args: dict) -> CommandResults:
    response = client.document_delete(args['folder'], args['document'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.document_delete',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_move_command(client: Client, args: dict) -> CommandResults:
    response = client.document_move(args['srcfolder'], args['dstfolder'], args['document'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.document_move',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_get_command(client: Client, args: dict) -> CommandResults:
    response = client.document_get(args['folder'], args['document'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.document_move',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_upload_file_command(client: Client, args: dict) -> CommandResults:
    response = client.document_upload_file(args['fileentry'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.upload_file',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_upload_link_command(client: Client, args: dict) -> CommandResults:
    response = client.document_upload_text(
        args['link'],
        args['title'],
        args['description'],
        args['author'],
        args['source']
    )
    return CommandResults(
        outputs_prefix = 'AnythingLLM.upload_link',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def document_upload_text_command(client: Client, args: dict) -> CommandResults:
    response = client.document_upload_text(
        args['text'],
        args['title'],
        args['description'],
        args['author'],
        args['source']
    )
    return CommandResults(
        outputs_prefix = 'AnythingLLM.upload_text',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_delete_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_delete(args['workspace'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_delete',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_get_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_get(args['workspace'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_get',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_list_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_list()
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_list',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_new_command(client: Client, args: dict) -> CommandResults:
    #if 'workspace' in args:
    response = client.workspace_new(args['workspace'])
    return CommandResults(
        outputs_prefix ='AnythingLLM.workspace_new',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )

    #msg = f"AnythingLLM: workspace_new_command: missing command arguments [workspace]"
    #demisto.debug(msg)
    #raise Exception(msg)


def workspace_chat_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_chat(args['workspace'], args['message'], args['mode'])
    return CommandResults(
        outputs_prefix ='AnythingLLM.workspace_chat',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_stream_chat_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_stream_chat(args['workspace'], args['message'], args['mode'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_stream_chat',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_delete_embedding_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_delete_embedding(args['workspace'], args['folder'], args['document'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_delete_embedding',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_add_embedding_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_add_embedding(args['workspace'], args['folder'], args['document'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_add_embedding',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_pin_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_pin(args['workspace'], args['folder'], args['document'], args['status'])
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_pin',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def workspace_settings_command(client: Client, args: dict) -> CommandResults:
    response = client.workspace_settings(args['workspace'], json.loads(args['settings']))
    return CommandResults(
        outputs_prefix = 'AnythingLLM.workspace_settings',
        readable_output = DictMarkdown(response, ""),
        outputs = response
    )


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        headers = {
            'accept': "application/json",
            'Authorization': f"Bearer {params.get('apikey')['password']}",
            'Content-Type': "application/json"
        }
        client = Client(
            base_url = params.get('url') + "/api",
            verify = not params.get('insecure', False),
            headers = headers,
            proxy = params.get('proxy', False)
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        #elif command == "anyllm-list":
        #    return_results(list_command(client, args))
        #elif command == "anyllm-settings":
        #    return_results(settings_command(client, args))

        elif command == "anyllm-document-list":
            return_results(document_list_command(client, args))
        elif command == "anyllm-document-createfolder":
            return_results(document_createfolder_command(client, args))
        elif command == "anyllm-document-get":
            return_results(document_get_command(client, args))
        elif command == "anyllm-document-move":
            return_results(document_move_command(client, args))
        elif command == "anyllm-document-delete":
            return_results(document_delete_command(client, args))
        elif command == "anyllm-document-upload-file":
            return_results(document_upload_file_command(client, args))
        elif command == "anyllm-document-upload-link":
            return_results(document_upload_link_command(client, args))
        elif command == "anyllm-document-upload-text":
            return_results(document_upload_text_command(client, args))

        elif command == "anyllm-workspace-get":
            return_results(workspace_get_command(client, args))
        elif command == "anyllm-workspace-list":
            return_results(workspace_list_command(client, args))
        elif command == "anyllm-workspace-new":
            return_results(workspace_new_command(client, args))
        elif command == "anyllm-workspace-chat":
            return_results(workspace_chat_command(client, args))
        elif command == "anyllm-workspace-stream-chat":
            return_results(workspace_stream_chat_command(client, args))
        elif command == "anyllm-workspace-delete-embedding":
            return_results(workspace_delete_embedding_command(client, args))
        elif command == "anyllm-workspace-add-embedding":
            return_results(workspace_add_embedding_command(client, args))
        elif command == "anyllm-workspace-pin":
            return_results(workspace_pin_command(client, args))
        elif command == "anyllm-workspace-delete":
            return_results(workspace_delete_command(client, args))
        elif command == "anyllm-workspace-settings":
            return_results(workspace_settings_command(client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
