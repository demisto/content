import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import math


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def list_local_models(self):
        response = self._http_request('GET', 'tags')
        return response

    def pull_model(self, model_name):
        response = self._http_request('POST', 'pull', json_data={
            'name': model_name,
            'stream': False
        })
        return response

    def delete_model(self, model_name):
        response = self._http_request('DELETE', 'delete', json_data={
            'name': model_name
        })
        return response

    def create_model(self, model_name, model_file):
        response = self._http_request('POST', 'create', json_data={
            'name': model_name,
            'modelfile': model_file,
            'stream': False
        })
        return response

    def show_model_info(self, model_name):
        response = self._http_request('POST', 'show', json_data={
            'name': model_name
        })
        return response

    def generate(self, model_name, message):
        response = self._http_request('POST', 'generate', json_data={
            'model': model_name,
            'prompt': message,
            'stream': False
        })
        return response

    def chat(self, model_name, history):
        response = self._http_request('POST', 'chat', json_data={
            'model': model_name,
            'messages': history,
            'stream': False
        })
        return response


''' HELPER FUNCTIONS '''


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name}"


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params) -> str:
    try:
        client.list_local_models()
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        raise DemistoException(str(e))


def list_local_models_command(client):
    '''
    List models that are available locally.
    '''

    response = client.list_local_models()

    results = []
    for item in response['models']:
        new_item = {
            'Name': item['name'],
            'Size': convert_size(item['size'])
        }
        results.append(new_item)

    readable = tableToMarkdown(
        name='List Local Models', t=results,
        metadata='Click here to access the models available for download: [here](https://ollama.com/library).',
        removeNull=True
    )
    return CommandResults(
        readable_output=readable,
        outputs_prefix='ollama.models',
        outputs_key_field='ollama.models',
        outputs=response
    )


def pull_model_command(client, model_name):
    '''
    Download a model from the ollama library.
    Cancelled pulls are resumed from where they left off, and multiple calls will share the same download progress.
    '''

    response = client.pull_model(model_name)

    if response['status'] == 'success':
        readable = f'Successfully pulled the **{model_name}** model.'

        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.pull',
            outputs_key_field='ollama.pull',
            outputs=response
        )
    else:
        readable = f'Failed to pull **{model_name}**.'
        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.pull',
            outputs_key_field='ollama.pull',
            outputs=response
        )


def show_model_info_command(client, model_name):
    '''
    Show information about a model including details, modelfile, template, parameters, license, and system prompt.
    '''

    response = client.show_model_info(model_name)

    # return json.dumps(response, indent=4)

    readable = tableToMarkdown('results', response)

    return CommandResults(
        readable_output=readable,
        outputs_prefix='ollama.show',
        outputs_key_field='ollama.show',
        outputs=response
    )


def delete_model_command(client, model_name):
    '''
    Delete a model and its data.
    '''

    response = client.delete_model(model_name)

    if response is None:
        readable = f'Successfully deleted the **{model_name}** model.'

        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.delete',
            outputs_key_field='ollama.delete',
            outputs=response
        )
    else:
        readable = f'Failed to delete **{model_name}**.'
        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.delete',
            outputs_key_field='ollama.delete',
            outputs=response
        )


def create_model_command(client, model_name, model_file):
    '''
    Create a model from a Modelfile.
    '''

    response = client.create(model_name, model_file)

    readable = f"Successfully created **{model_name}**"

    return CommandResults(
        readable_output=readable,
        outputs_prefix='ollama.create',
        outputs_key_field='ollama.create',
        outputs=response
    )


def generate_command(client, model_name, message):
    '''
    Generate a response for a given prompt with a provided model.
    '''

    response = client.generate(model_name, message)
    readable = f"`{model_name}`: {response['response']}"

    return CommandResults(
        readable_output=readable,
        outputs_prefix='ollama.generate',
        outputs_key_field='ollama.generate',
        outputs=response['response']
    )


def conversation_command(client, model_name, message, history):
    '''
    Generate the next message in a chat with a provided model.
    '''

    if history == {}:
        response = client.generate(model_name, message)
        readable = f"`{model_name}`: {response['response']}"

        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.history',
            outputs_key_field='ollama.history',
            outputs=[
                {'role': 'user', 'content': message},
                {'role': 'assistant', 'content': response['response']}
            ]
        )

    else:
        history.append({'role': 'user', 'content': message})

        response = client.chat(model_name, history)

        readable = f"`{model_name}`: {response['message']['content']}"
        readable = f"{response['message']['content']}"

        return CommandResults(
            readable_output=readable,
            outputs_prefix='ollama.history',
            outputs_key_field='ollama.history',
            outputs=[
                {'role': 'user', 'content': message},
                response['message']
            ]
        )


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    context = demisto.context()

    protocol = params.get('protocol', 'https')
    host = params.get('host', 'localhost')
    port = params.get('port', 11434)
    path = params.get('path', '/api')
    base_url = f'{protocol}://{host}:{port}{path}'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        cf_client_id = params.get('cf_id', None)
        cf_client_key = params.get('cf_secret', None)
        default_model = params.get('default_model', None)
        model_name = args.get('model', default_model)

        headers = {}
        if cf_client_id is not None and cf_client_key is not None:
            headers = {
                'CF-Access-Client-Id': cf_client_id,
                'CF-Access-Client-Secret': cf_client_key
            }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            timeout=300)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, params)
            return_results(result)

        elif command == 'ollama-list-models':
            result = list_local_models_command(client)
            return_results(result)

        elif command == 'ollama-model-pull':
            result = pull_model_command(client, model_name)
            return_results(result)

        elif command == 'ollama-model-delete':
            result = delete_model_command(client, model_name)
            return_results(result)

        elif command == 'ollama-model-create':
            model_file = args.get('model_file', None)
            result = create_model_command(client, model_name, model_file)
            return_results(result)

        elif command == 'ollama-model-info':
            result = show_model_info_command(client, model_name)
            return_results(result)

        elif command == 'ollama-generate':
            message = args.get('message', None)
            result = generate_command(client, model_name, message)
            return_results(result)

        elif command == 'ollama-conversation':
            message = args.get('message', None)
            history = context.get('ollama', {}).get('history', {})
            result = conversation_command(client, model_name, message, history)
            return_results(result)

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute `{command}` command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
