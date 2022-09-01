import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_module(client) -> str:
    result = client._http_request('GET', '/usage')
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def run_command(client, data: Dict[str, str], endpoint: str, file=None, resp_type='json'):
    response = client._http_request('POST', endpoint, data=data, files=file, resp_type=resp_type)
    return response


def create_output(results: Dict[str, str], endpoint: str, keyfield=''):
    output = CommandResults(
        outputs_prefix=f'DeepL.{endpoint}',
        outputs_key_field=keyfield,
        outputs=results
    )
    return output


def main():
    apikey = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v2')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'Authorization': f'DeepL-Auth-Key {apikey}'}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'deepl-usage':
            data: Dict[str, str] = {}
            results = run_command(client, data, '/usage')
            return_results(create_output(results, 'Usage'))
        elif demisto.command() == 'deepl-translate-text':
            results = run_command(client, args, '/translate')
            return_results(create_output(results.get('translations'), 'TranslatedText'))
        elif demisto.command() == 'deepl-submit-document':
            data = args
            filename = demisto.args().get('file')
            data.pop('file')
            file = demisto.getFilePath(filename)
            with open(file['path'], 'rb') as open_file:
                results = run_command(client, data, '/document', {'file': (file['name'], open_file)})
            return_results(create_output(results, 'DocumentSubmission'))
        elif demisto.command() == 'deepl-check-document-status':
            data = {'document_key': args.get('document_key')}
            document_id = args.get('document_id')
            results = run_command(client, data, f'/document/{document_id}')
            return_results(create_output(results, 'DocumentStatus', 'document_id'))
        elif demisto.command() == 'deepl-get-document':
            data = {'document_key': args.get('document_key')}
            document_id = args.get('document_id')
            filename = args.get('filename')
            results = run_command(client, data, f'/document/{document_id}/result', resp_type='content')
            return_results(fileResult(filename, results, file_type=EntryType.ENTRY_INFO_FILE))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
