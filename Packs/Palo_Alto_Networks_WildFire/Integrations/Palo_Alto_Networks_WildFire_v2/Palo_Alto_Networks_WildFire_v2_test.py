from requests import Response

import demistomock as demisto
from Palo_Alto_Networks_WildFire_v2 import prettify_upload, prettify_report_entry, prettify_verdict, \
    create_dbot_score_from_verdict, prettify_verdicts, create_dbot_score_from_verdicts, hash_args_handler, \
    file_args_handler, wildfire_get_sample_command, wildfire_get_report_command


def test_will_return_ok():
    assert 1 == 1


def test_prettify_upload():
    expected_upload_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'FileType': "pdf", 'Size': 5, 'Status': "Pending"})
    prettify_upload_res = prettify_upload(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'filetype': "pdf", 'size': 5})
    assert expected_upload_dict == prettify_upload_res


def test_prettify_report_entry():
    expected_report_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'FileType': "pdf", 'Size': 5, 'Status': "Completed"})
    prettify_report_entry_res = prettify_report_entry(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'filetype': "pdf", 'size': 5})
    assert expected_report_dict == prettify_report_entry_res


def test_prettify_verdict():
    expected_verdict_dict = dict({
        'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'malware'})
    prettify_verdict_res = prettify_verdict(
        {'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"})
    assert expected_verdict_dict == prettify_verdict_res


def test_create_dbot_score_from_verdict():
    expected_dbot_score = [
        {
            'Indicator': "sha256_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 3,
            'Reliability': 'B - Usually reliable'
        },
        {
            'Indicator': "sha256_hash", 'Type': "file", 'Vendor': "WildFire", 'Score': 3,
            'Reliability': 'B - Usually reliable'
        },
    ]
    dbot_score_dict = create_dbot_score_from_verdict({'SHA256': "sha256_hash", 'Verdict': "1"})
    assert expected_dbot_score == dbot_score_dict


def test_prettify_verdicts():
    expected_verdicts_dict = [
        {'MD5': "md5_hash", 'SHA256': "sha256_hash", 'Verdict': "1", 'VerdictDescription': 'malware'}]
    prettify_verdicts_res = prettify_verdicts(
        [{'md5': "md5_hash", 'sha256': "sha256_hash", 'verdict': "1"}])
    assert expected_verdicts_dict == prettify_verdicts_res


def test_create_dbot_score_from_verdicts():
    expected_dbot_scores = [{'Indicator': "sha256_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 3,
                             'Reliability': 'B - Usually reliable'},
                            {'Indicator': "sha256_hash", 'Type': "file", 'Vendor': "WildFire", 'Score': 3,
                             'Reliability': 'B - Usually reliable'},
                            {'Indicator': "md5_hash", 'Type': "hash", 'Vendor': "WildFire", 'Score': 1,
                             'Reliability': 'B - Usually reliable'},
                            {'Indicator': "md5_hash", 'Type': "file", 'Vendor': "WildFire", 'Score': 1,
                             'Reliability': 'B - Usually reliable'}]
    dbot_score_dict = create_dbot_score_from_verdicts(
        [{'SHA256': "sha256_hash", 'Verdict': '1'}, {'MD5': "md5_hash", 'Verdict': '0'}])
    assert expected_dbot_scores == dbot_score_dict


def test_hash_args_handler():
    expected_hash_list = ['12345678901234567890123456789012']
    hash_list = hash_args_handler(md5='12345678901234567890123456789012')
    assert expected_hash_list == hash_list


def test_file_args_handler():
    expected_file_hash_list = ['12345678901234567890123456789012',
                               '1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3']
    file_hash_list = file_args_handler(
        file="12345678901234567890123456789012,1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3")
    assert expected_file_hash_list == file_hash_list


def test_get_sample(mocker):
    """
    Given:
     - SHA-256 hash of sample to get.

    When:
     - Running get-sample command.

    Then:
     - Verify file with the expected name is returned.
    """
    mocker.patch.object(demisto, 'results')
    filename = '1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3.xlsx'
    get_sample_response = Response()
    get_sample_response.status_code = 200
    get_sample_response.headers = {
        'Server': 'nginx',
        'Date': 'Thu, 28 May 2020 15:03:35 GMT',
        'Content-Type': 'application/octet-stream',
        'Transfer-Encoding': 'chunked',
        'Connection': 'keep-alive',
        'Content-Disposition': f'attachment; filename={filename}.000',
        'x-envoy-upstream-service-time': '258'
    }
    get_sample_response._content = 'filecontent'.encode()
    mocker.patch(
        'Palo_Alto_Networks_WildFire_v2.wildfire_get_sample',
        return_value=get_sample_response
    )
    mocker.patch.object(
        demisto,
        'args',
        return_value={
            'sha256': '1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3'
        }
    )
    wildfire_get_sample_command()
    results = demisto.results.call_args[0]
    assert results[0]['File'] == filename


def test_report_chunked_response(mocker):
    """
    Given:
     - hash of file.

    When:
     - Running report command.

    Then:
     - outputs is valid.
    """
    mocker.patch.object(demisto, 'results')
    get_sample_response = Response()
    get_sample_response.status_code = 200
    get_sample_response.headers = {
        'Server': 'nginx',
        'Date': 'Thu, 28 May 2020 15:03:35 GMT',
        'Transfer-Encoding': 'chunked',
        'Connection': 'keep-alive',
        'x-envoy-upstream-service-time': '258'
    }
    get_sample_response._content = b'<?xml version="1.0" encoding="UTF-8"?><wildfire><version>2.0</version><file_info>' \
                                   b'<file_signer>None</file_signer><malware>no</malware><sha1></sha1><filetype>PDF' \
                                   b'</filetype><sha256>' \
                                   b'8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51</sha256><md5>' \
                                   b'4b41a3475132bd861b30a878e30aa56a</md5><size>3028</size></file_info><task_info>' \
                                   b'<report><version>2.0</version><platform>100</platform><software>' \
                                   b'PDF Static Analyzer</software><sha256>' \
                                   b'8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51</sha256>' \
                                   b'<md5>4b41a3475132bd861b30a878e30aa56a</md5><malware>no</malware><summary/>' \
                                   b'</report></task_info></wildfire>'
    mocker.patch(
        'requests.request',
        return_value=get_sample_response
    )
    mocker.patch.object(demisto, "args",
                        return_value={'hash': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51',
                                      'format': 'xml'})
    mocker.patch("Palo_Alto_Networks_WildFire_v2.URL", "https://wildfire.paloaltonetworks.com/publicapi")
    wildfire_get_report_command()
    result = {'Type': 1,
              'Contents': [{'version': '2.0', 'platform': '100', 'software': 'PDF Static Analyzer',
                            'sha256': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51',
                            'md5': '4b41a3475132bd861b30a878e30aa56a', 'malware': 'no', 'summary': None}],
              'ContentsFormat': 'json',
              'HumanReadable': '### WildFire File Report\n|FileType|MD5|SHA256|Size|Status|\n|---|---|---|---|---|\n'
                               '| PDF | 4b41a3475132bd861b30a878e30aa56a | '
                               '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 | 3028 '
                               '| Completed |\n',
              'ReadableContentsFormat': 'markdown',
              'EntryContext':
                  {'WildFire.Report(val.SHA256 === obj.SHA256)': {
                      'Status': 'Success',
                      'SHA256': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51'},
                      'DBotScore': [
                          {'Indicator': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51',
                           'Type': 'hash',
                           'Vendor': 'WildFire', 'Score': 1, 'Reliability': 'B - Usually reliable'},
                          {'Indicator': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51',
                           'Type': 'file',
                           'Vendor': 'WildFire', 'Score': 1, 'Reliability': 'B - Usually reliable'}]}}
    assert demisto.results.call_args[0][0] == result
