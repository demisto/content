import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=verify)

    def get_info(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/info'
        )

    def get_top_stats(self) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/stats/top'
        )

    def bulk_search(self, hashtype: str, data: Dict[str, List[str]]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'/bulk/{hashtype}',
            json_data=data
        )

    def file_search(self, hashtype: str, hashvalue: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/lookup/{hashtype}/{hashvalue}'
        )


def test_module(client) -> str:
    result = client._http_request('GET', '/info')
    if result:
        return 'ok'
    else:
        return 'Test failed: ' + str(result)


def correct_output_keys(results: Dict[str, str]) -> Dict[str, str]:
    newoutput = {}
    if 'FileName' in results:
        newoutput['Name'] = results.pop('FileName')
    if 'FileSize' in results:
        newoutput['Size'] = results.pop('FileSize')
    if 'MD5' in results:
        newoutput['MD5'] = results.pop('MD5')
    if 'SHA-1' in results:
        newoutput['SHA1'] = results.pop('SHA-1')
    if 'SHA-256' in results:
        newoutput['SHA1'] = results.pop('SHA-256')
    if 'SHA-512' in results:
        newoutput['SHA1'] = results.pop('SHA-512')
    if 'SSDEEP' in results:
        newoutput['SSDeep'] = results.pop('SSDEEP')
    newoutput.update(results)
    return newoutput


def relationship_creator(entity_a, entity_b_list, reliability) -> List[EntityRelationship]:
    list_of_relationships = []
    for item in entity_b_list:
        if item.get('SHA-256'):
            entity_b = item.get('SHA-256')
        elif item.get('SHA-1'):
            entity_b = item.get('SHA-1')
        else:
            entity_b = item.get('MD5')

        relation_by_type = 'related-to'
        list_of_relationships.append(EntityRelationship(name=relation_by_type,
                                                        entity_a=entity_a,
                                                        entity_a_type='File',
                                                        entity_b=entity_b,
                                                        entity_b_type='File',
                                                        source_reliability=reliability,
                                                        brand='Circl'))
    return list_of_relationships


def create_file_output(results: Dict[str, str], hashtype: str, reliability: str, create_relationships: bool) -> CommandResults:
    relationships = []
    if hashtype == 'sha256':
        file_hash = results.get('SHA-256')
    elif hashtype == 'sha1':
        file_hash = results.get('SHA-1')
    elif hashtype == 'md5':
        file_hash = results.get('MD5')
    else:
        file_hash = ""
        demisto.debug(f"{hashtype=} doesn't match any type. {file_hash=}")

    if 'KnownMalicious' in results:
        dbot_score_object = Common.DBotScore(indicator=file_hash, indicator_type=DBotScoreType.FILE,
                                             integration_name='Circl', score=3, reliability=reliability)
    else:
        dbot_score_object = Common.DBotScore(indicator=file_hash, indicator_type=DBotScoreType.FILE,
                                             integration_name='Circl', score=0, reliability=reliability)

    file = Common.File(dbot_score=dbot_score_object, name=results.get('FileName'),
                       file_type=results.get('mimetype'), md5=results.get('MD5'), sha1=results.get('SHA-1'),
                       sha256=results.get('SHA-256'), size=results.get('FileSize'), ssdeep=results.get('SSDEEP'))

    if create_relationships:
        parents = results.get('parents')
        if parents:
            relationships = relationship_creator(file_hash, parents, reliability)

    modifiedresults = correct_output_keys(results)
    human_readable = tableToMarkdown('Cirlc hashlookup results', modifiedresults)

    output = CommandResults(
        outputs_prefix='File',
        outputs_key_field=file_hash,
        outputs=modifiedresults,
        indicator=file,
        relationships=relationships,
        readable_output=human_readable
    )
    return output


def create_output(results: Dict[str, str], endpoint: str, keyfield: str = '') -> CommandResults:
    human_readable = tableToMarkdown('Circl results', results)
    output = CommandResults(
        outputs_prefix=f'CIRCL.{endpoint}',
        outputs_key_field=keyfield,
        outputs=results,
        readable_output=human_readable
    )
    return output


def main():

    # get the service API url
    reliability = demisto.params().get('integrationReliability', DBotScoreReliability.B)
    create_relationships = demisto.params().get('create_relationships', True)
    base_url = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    headers = {'Accept': 'application/json',
               'Content-type': 'application/json'}

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)
        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'circl-info':
            results = client.get_info()
            return_results(create_output(results, 'Info'))
        elif demisto.command() == 'circl-top':
            results = client.get_top_stats()
            return_results(create_output(results, 'Top'))
        elif demisto.command() == 'circl-bulk-md5':
            md5list = argToList(args.get('md5_list'))
            data = {'hashes': md5list}
            results = client.bulk_search('md5', data)
            return_results(create_output(results, 'MD5'))
        elif demisto.command() == 'circl-bulk-sha1':
            sha1list = argToList(args.get('sha1_list'))
            data = {'hashes': sha1list}
            results = client.bulk_search('sha1', data)
            return_results(create_output(results, 'SHA1'))
        elif demisto.command() == 'file':
            file_list = argToList(args.get('file'))
            if len(file_list) == 0:
                raise ValueError('Hash(es) not specified')
            for item in file_list:
                if len(item) == 32:
                    results = client.file_search('md5', item)
                    return_results(create_file_output(results, 'md5', reliability, create_relationships))
                elif len(item) == 40:
                    results = client.file_search('sha1', item)
                    return_results(create_file_output(results, 'sha1', reliability, create_relationships))
                elif len(item) == 64:
                    results = client.file_search('sha256', item)
                    return_results(create_file_output(results, 'sha256', reliability, create_relationships))
                else:
                    return_error('Hash value not valid md5, sha1 or sha256')

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
