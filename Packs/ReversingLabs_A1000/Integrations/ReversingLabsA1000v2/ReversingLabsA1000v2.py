from CommonServerPython import *
from ReversingLabs.SDK.a1000 import A1000

VERSION = "v2.0.0"
USER_AGENT = f"ReversingLabs XSOAR A1000 {VERSION}"
HOST = demisto.getParam('host')
TOKEN = demisto.getParam('token')
VERIFY_CERT = demisto.getParam('verify')
RELIABILITY = demisto.params().get('reliability', 'C - Fairly reliable')
WAIT_TIME_SECONDS = demisto.params().get('wait_time_seconds')
NUM_OF_RETRIES = demisto.params().get('num_of_retries')


def classification_to_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "KNOWN": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification, 0)


def test(a1000):
    """
    Test credentials and connectivity
    """
    try:
        a1000.test_connection()
        return 'ok'
    except Exception as e:
        return_error(str(e))


def get_results(a1000):
    """
    Get A1000 report
    """
    try:
        hash_value = demisto.getArg('hash')
        response_json = a1000.get_results(hash_value).json()
    except Exception as e:
        return_error(str(e))

    command_result = a1000_report_output(response_json)

    file_result = fileResult('A1000 report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return_results([command_result, file_result])


def upload_sample_and_get_results(a1000):
    """
    Upload file to A1000 and get report
    """
    file_entry = demisto.getFilePath(demisto.getArg('entryId'))

    try:
        with open(file_entry['path'], 'rb') as f:
            response_json = a1000.upload_sample_and_get_results(file_source=f,
                                                                custom_filename=file_entry.get('name'),
                                                                tags=demisto.getArg('tags'),
                                                                comment=demisto.getArg('comment')).json()
    except Exception as e:
        return_error(str(e))

    command_result = a1000_report_output(response_json)

    file_result = fileResult('A1000 report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def a1000_report_output(response_json):
    results = response_json.get('results')
    result = results[0] if results else {}
    status = result.get('threat_status', '')
    d_bot_score = classification_to_score(status.upper())

    md5 = result.get('md5')
    sha1 = result.get('sha1')
    sha256 = result.get('sha256')
    sha512 = result.get('sha512')
    file_type = result.get('file_type')
    file_subtype = result.get('file_subtype')
    file_size = result.get('file_size')

    markdown = f'''## ReversingLabs A1000 results for: {result.get('sha1')}\n **Type:** {file_type}/{file_subtype}
    **Size:** {file_size} bytes \n'''

    if md5:
        markdown += f'**MD5:** {md5}\n'
    if sha1:
        markdown += f'**SHA1:** {sha1}\n'
    if sha256:
        markdown += f'**SHA256:** {sha256}\n'
    if sha512:
        markdown += f'**SHA512:** {sha512}\n'

    markdown += f'''**ID:** {demisto.get(result, 'summary.id')}
    **Malware status:** {format(status)}
    **Local first seen:** {result.get('local_first_seen')}
    **Local last seen:** {result.get('local_last_seen')}
    **First seen:** {demisto.gets(result, 'ticloud.first_seen')}
    **Last seen:** {demisto.gets(result, 'ticloud.last_seen')}
    **DBot score:** {d_bot_score}
    **Trust factor:** {result.get('trust_factor')} \n'''
    if status == 'malicious':
        markdown += f'''**Threat name:** {result.get('threat_name')}
                **Threat level:** {result.get('threat_level')}'''
    markdown += f'''\n **Category:** {result.get('category')}
    **Classification origin:** {result.get('classification_origin')}
    **Classification reason:** {result.get('classification_reason')}
    **Aliases:** {','.join(result.get('aliases'))}
    **Extracted file count:** {result.get('extracted_file_count')}
    **Identification name:** {result.get('identification_name')}
    **Identification version:** {result.get('identification_version')}\n'''
    indicators = demisto.get(result, 'summary.indicators')
    if indicators:
        markdown += tableToMarkdown('ReversingLabs threat indicators', indicators)

    dbot_score = Common.DBotScore(
        indicator=sha1,
        indicator_type=DBotScoreType.FILE,
        integration_name='ReversingLabs A1000',
        score=d_bot_score,
        malicious_description=f"{result.get('classification_reason')} - {result.get('threat_name')}",
        reliability=RELIABILITY
    )

    common_file = Common.File(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        dbot_score=dbot_score
    )

    command_results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_report': response_json},
        readable_output=markdown,
        indicator=common_file
    )
    return command_results


def upload_sample(a1000):
    """
    Upload file to A1000 for analysis
    """
    file_entry = demisto.getFilePath(demisto.getArg('entryId'))

    try:
        with open(file_entry['path'], 'rb') as f:
            response_json = a1000.upload_sample_from_file(f,
                                                          custom_filename=file_entry.get('name'),
                                                          tags=demisto.getArg('tags'),
                                                          comment=demisto.getArg('comment')).json()
    except Exception as e:
        return_error(str(e))

    markdown = f'''## ReversingLabs A1000 upload sample\n **Message:** {response_json.get('message')}
    **ID:** {demisto.get(response_json, 'detail.id')}
    **SHA1:** {demisto.get(response_json, 'detail.sha1')}
    **Created:** {demisto.get(response_json, 'detail.created')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_upload_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('Upload sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def delete_sample(a1000):
    """
    Delete a file from A1000
    """
    hash_value = demisto.getArg('hash')
    try:
        response_json = a1000.delete_samples(hash_value).json()
    except Exception as e:
        return_error(str(e))

    res = response_json.get('results')
    markdown = f'''## ReversingLabs A1000 delete sample\n **Message:** {res.get('message')}
    **MD5:** {demisto.get(res, 'detail.md5')}
    **SHA1:** {demisto.get(res, 'detail.sha1')}
    **SHA256:** {demisto.get(res, 'detail.sha256')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_delete_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('Delete sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def reanalyze(a1000):
    """
    Re-Analyze a sample already existing on A1000
    """
    hash_value = demisto.getArg('hash')
    try:
        response_json = a1000.reanalyze_samples(hash_value).json()
    except Exception as e:
        return_error(str(e))

    markdown = f'''## ReversingLabs A1000 re-analyze sample\n**Message:** {response_json.get('message')}
    **MD5:** {demisto.get(response_json, 'detail.md5')}
    **SHA1:** {demisto.get(response_json, 'detail.sha1')}
    **SHA256:** {demisto.get(response_json, 'detail.sha256')}'''

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_reanalyze_report': response_json},
        readable_output=markdown
    )

    file_result = fileResult('ReAnalyze sample report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def list_extracted_files(a1000):
    """
    Get the list of extracted files for a given sample
    """
    hash_value = demisto.getArg('hash')

    try:
        response_json = a1000.get_extracted_files(hash_value).json()
    except Exception as e:
        return_error(str(e))

    command_result = list_extracted_files_output(response_json)

    file_result = fileResult('List extracted files report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def list_extracted_files_output(response_json):
    results = response_json.get('results')

    file_list = []
    for result in results:
        sha1 = demisto.get(result, 'sample.sha1')
        status = demisto.get(result, 'sample.threat_status')
        file_data = {
            'SHA1': sha1,
            'Name': result.get('filename'),
            'Info': demisto.get(result, 'sample.type_display'),
            'Size': demisto.get(result, 'sample.file_size'),
            'Path': result.get('path'),
            'Local First': demisto.get(result, 'sample.local_first_seen'),
            'Local Last': demisto.get(result, 'sample.local_last_seen'),
            'Malware Status': status,
            'Trust': demisto.get(result, 'sample.trust_factor'),
            'Threat Name': demisto.get(result, 'sample.threat_name'),
            'Threat Level': demisto.get(result, 'sample.threat_level')
        }

        file_list.append(file_data)

    markdown = tableToMarkdown('Extracted files', file_list,
                               ['SHA1', 'Name', 'Path', 'Info', 'Size', 'Local First', 'Local Last',
                                'Malware Status', 'Trust', 'Threat Name', 'Threat Level'])

    command_results = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_list_extracted_report': response_json},
        readable_output=markdown,
    )

    return command_results


def download_extracted_files(a1000):
    """
    Download samples obtained through the unpacking process
    """
    hash_value = demisto.getArg('hash')
    try:
        response = a1000.download_extracted_files(hash_value)
    except Exception as e:
        return_error(str(e))

    filename = hash_value + '.zip'
    command_results = CommandResults(
        readable_output=f"## ReversingLabs A1000 download extraced files \nExtracted files are available for download "
                        f"under the name {filename}"
    )

    file_result = fileResult(filename, response.content, file_type=EntryType.FILE)

    return [command_results, file_result]


def download_sample(a1000):
    """
    Download a sample from A1000
    """
    hash_value = demisto.getArg('hash')

    try:
        response = a1000.download_sample(hash_value)
    except Exception as e:
        return_error(str(e))

    command_results = CommandResults(
        readable_output=f"## ReversingLabs A1000 download sample \nRequested sample is available for download under "
                        f"the name {hash_value}"
    )

    file_result = fileResult(hash_value, response.content, file_type=EntryType.FILE)

    return [command_results, file_result]


def get_classification(a1000):
    """
    Download samples obtained through the unpacking process
    """
    hash_value = demisto.getArg('hash')

    try:
        response_json = a1000.get_classification(hash_value).json()
    except Exception as e:
        return_error(str(e))

    command_result = get_classification_output(response_json)
    file_result = fileResult('Get classification report file', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def get_classification_output(response_json):
    markdown = f"## ReversingLabs A1000 get classification for sha1: {response_json.get('sha1')}\n"
    for key, value in response_json.items():
        markdown += f'**{str.capitalize(key.replace("_", " "))}:** {value}\n'

    status = response_json.get('threat_status')
    if status:
        d_bot_score = classification_to_score(status.upper())
        dbot_score = Common.DBotScore(
            indicator=response_json.get('sha1'),
            indicator_type=DBotScoreType.FILE,
            integration_name='ReversingLabs A1000',
            score=d_bot_score,
            malicious_description=status,
            reliability=RELIABILITY
        )

        common_file = Common.File(
            md5=response_json.get('md5'),
            sha1=response_json.get('sha1'),
            sha256=response_json.get('sha256'),
            dbot_score=dbot_score
        )

        command_results = CommandResults(
            outputs_prefix='ReversingLabs',
            outputs={'a1000_classification_report': response_json},
            indicator=common_file,
            readable_output=markdown
        )
        return command_results


def advanced_search(a1000):
    """
    Advanced Search by query
    """
    query = demisto.getArg('query')

    try:
        limit = demisto.getArg("result-limit")
        if not isinstance(limit, int):
            limit = int(limit)
    except KeyError:
        limit = 5000

    try:
        result_list = a1000.advanced_search_aggregated(query_string=query, max_results=limit)
    except Exception as e:
        return_error(str(e))

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'a1000_advanced_search_report': result_list},
        readable_output="## Reversinglabs A1000 advanced Search \nFull report is returned in a downloadable file"
    )

    file_result = fileResult('Advanced search report file', json.dumps(result_list, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def main():

    try:
        wait_time_seconds = int(WAIT_TIME_SECONDS)
    except ValueError:
        return_error("Integration parameter <Wait between retries> has to be of type integer.")

    try:
        num_of_retries = int(NUM_OF_RETRIES)
    except ValueError:
        return_error("Integration parameter <Number of retries> has to be of type integer.")

    a1000 = A1000(
        host=HOST,
        token=TOKEN,
        verify=VERIFY_CERT,
        user_agent=USER_AGENT,
        wait_time_seconds=wait_time_seconds,
        retries=num_of_retries
    )

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'test-module':
            return_results(test(a1000))
        elif demisto.command() == 'reversinglabs-a1000-get-results':
            return_results(get_results(a1000))
        elif demisto.command() == 'reversinglabs-a1000-upload-sample-and-get-results':
            return_results(upload_sample_and_get_results(a1000))
        elif demisto.command() == 'reversinglabs-a1000-upload-sample':
            return_results(upload_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-delete-sample':
            return_results(delete_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-list-extracted-files':
            return_results(list_extracted_files(a1000))
        elif demisto.command() == 'reversinglabs-a1000-download-sample':
            return_results(download_sample(a1000))
        elif demisto.command() == 'reversinglabs-a1000-reanalyze':
            return_results(reanalyze(a1000))
        elif demisto.command() == 'reversinglabs-a1000-download-extracted-files':
            return_results(download_extracted_files(a1000))
        elif demisto.command() == 'reversinglabs-a1000-get-classification':
            return_results(get_classification(a1000))
        elif demisto.command() == 'reversinglabs-a1000-advanced-search':
            return_results(advanced_search(a1000))
        else:
            return_error(f'Command [{demisto.command()}] not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
