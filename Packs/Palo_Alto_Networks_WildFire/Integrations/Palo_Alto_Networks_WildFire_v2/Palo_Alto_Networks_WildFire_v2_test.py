import json
import io

from requests import Response

import demistomock as demisto
from Palo_Alto_Networks_WildFire_v2 import prettify_upload, prettify_report_entry, prettify_verdict, \
    create_dbot_score_from_verdict, prettify_verdicts, create_dbot_score_from_verdicts, hash_args_handler, \
    file_args_handler, wildfire_get_sample_command, wildfire_get_report_command, run_polling_command, \
    wildfire_upload_url_command, prettify_url_verdict, create_dbot_score_from_url_verdict, parse_file_report


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


def test_prettify_url_verdict():
    """
    Given:
     - The verdict response.

    When:
     - Running prettify_url_verdict function.

    Then:
     - Verify that the dictionary is prettified.
    """
    expected_verdict_dict = dict({'URL': 'www.some-url.com', 'Verdict': '0', 'VerdictDescription': 'benign',
                                  'Valid': 'Yes', 'AnalysisTime': '2021-12-13T11:30:55Z'})
    prettify_verdict_res = prettify_url_verdict(
        {'url': 'www.some-url.com', 'verdict': '0', 'analysis_time': '2021-12-13T11:30:55Z', 'valid': 'Yes'})
    assert expected_verdict_dict == prettify_verdict_res


def test_create_dbot_score_from_url_verdict():
    """
    Given:
     - A dictionary to create the dbot score from.

    When:
     - Running create_dbot_score_from_url_verdict function.

    Then:
     - Verify that the expected dbot score has been returned.
    """
    expected_dbot_score = [
        {'Indicator': 'www.some-url.com', 'Type': 'url', 'Vendor': 'WildFire', 'Score': 1,
         'Reliability': 'B - Usually reliable'}
    ]
    dbot_score_dict = create_dbot_score_from_url_verdict({'URL': "www.some-url.com", 'Verdict': "0"})
    assert expected_dbot_score == dbot_score_dict


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
    command_results, status = wildfire_get_report_command(
        {'hash': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51',
         'format': 'xml'})
    hr = '### WildFire File Report\n|FileType|MD5|SHA256|Size|Status|\n|---|---|---|---|---|\n|' \
         ' PDF | 4b41a3475132bd861b30a878e30aa56a | 8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51 |' \
         ' 3028 | Completed |\n'
    context = {'Status': 'Success', 'SHA256': '8decc8571946d4cd70a024949e033a2a2a54377fe9f1c1b944c20f9ee11a9e51'}

    assert command_results[0].outputs == context
    assert command_results[0].readable_output == hr


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_running_polling_command_success(mocker):
    """
    Given:
        An upload request of a url or a file using the polling flow, that was already initiated priorly and is now
         complete.
    When:
        When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         already complete.
    Then:
        Return a command results object, without scheduling a new command.
    """
    args = {'url': 'www.google.com'}
    response_upload = util_load_json('./tests_data/upload_url_response.json')
    upload_url_data = {'url': 'https://www.demisto.com',
                       'sha256': 'c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb',
                       'md5': '67632f32e6af123aa8ffd1fe8765a783'}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch('Palo_Alto_Networks_WildFire_v2.wildfire_upload_url', return_value=(response_upload, upload_url_data))
    response_report = util_load_json('./tests_data/report_url_response_success.json')
    mocker.patch('Palo_Alto_Networks_WildFire_v2.http_request', return_value=response_report)
    expected_outputs = util_load_json('./tests_data/expected_outputs_upload_url_success.json')
    command_results = run_polling_command(args, 'wildfire-upload-url', wildfire_upload_url_command,
                                          wildfire_get_report_command, 'URL')
    assert command_results[0].outputs.get('detection_reasons') == expected_outputs.get('detection_reasons')
    assert command_results[0].scheduled_command is None


def test_running_polling_command_pending(mocker):
    """
    Given:
         An upload request of a url or a file using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = {'url': 'wwwdom'}
    response_upload = util_load_json('./tests_data/upload_url_response.json')
    upload_url_data = {'url': 'https://www.demisto.com',
                       'sha256': 'c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb',
                       'md5': '67632f32e6af123aa8ffd1fe8765a783'}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    mocker.patch('Palo_Alto_Networks_WildFire_v2.wildfire_upload_url', return_value=(response_upload, upload_url_data))
    response_report = util_load_json('./tests_data/report_url_response_pending.json')
    mocker.patch('Palo_Alto_Networks_WildFire_v2.http_request', return_value=response_report)
    command_results = run_polling_command(args, 'wildfire-upload-url', wildfire_upload_url_command,
                                          wildfire_get_report_command, 'URL')
    assert command_results[0].outputs is None
    assert command_results[0].scheduled_command is not None


def test_running_polling_command_new_search(mocker):
    """
    Given:
         An upload request of a url or a file using the polling flow, that was already initiated priorly and is not
          completed yet.
    When:
         When, while in the polling flow, we are checking the status of on an upload that was initiated earlier and is
         not complete yet.
    Then:
        Return a command results object, with scheduling a new command.
    """
    args = {'upload': 'https://www.demisto.com'}
    mocker.patch('CommonServerPython.ScheduledCommand.raise_error_if_not_supported')
    response_upload = util_load_json('./tests_data/upload_url_response.json')
    upload_url_data = {'url': 'https://www.demisto.com',
                       'sha256': 'c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb',
                       'md5': '67632f32e6af123aa8ffd1fe8765a783'}
    mocker.patch('Palo_Alto_Networks_WildFire_v2.wildfire_upload_url', return_value=(response_upload, upload_url_data))
    response_report = util_load_json('./tests_data/report_url_response_pending.json')
    mocker.patch('Palo_Alto_Networks_WildFire_v2.http_request', return_value=response_report)
    command_results = run_polling_command(args, 'wildfire-upload-url', wildfire_upload_url_command,
                                          wildfire_get_report_command, 'URL')
    expected_outputs = {'MD5': '67632f32e6af123aa8ffd1fe8765a783',
                        'SHA256': 'c51a8231d1be07a2545ac99e86a25c5d68f88380b7ebf7ac91501661e6d678bb',
                        'Status': 'Pending', 'URL': 'https://www.demisto.com'}
    assert command_results[0].outputs == expected_outputs
    assert command_results[0].scheduled_command is not None


def test_parse_file_report_network():
    """
    Given:
        - A report json from a WildFire response of the 'wildfire-report' command, that includes Network details.
    When:
        - Running 'parse_file_report' function.
    Then:
        - Verify that the Network details (TCP, UDP, DNS) are parsed correctly.
    """
    report = {
        "evidence":
            {
                "file": None,
                "mutex": None,
                "process": None,
                "registry": None
            },
        "malware": "yes",
        "md5": "test",
        "network":
            {
                "TCP":
                    [
                        {
                            "@country": "US",
                            "@ip": "1.1.1.1",
                            "@ja3": "test",
                            "@ja3s": "test",
                            "@port": "443"
                        },
                        {
                            "@country": "US",
                            "@ip": "1.0.1.0",
                            "@ja3": "test",
                            "@ja3s": "",
                            "@port": "80"
                        }
                    ],
                "UDP":
                    {
                        "@country": "US",
                        "@ip": "1.1.1.1",
                        "@ja3": "test",
                        "@ja3s": "test",
                        "@port": "55"
                    },
                "dns":
                    {
                        "@query": "test.com",
                        "@response": "1.1.1.1.",
                        "@type": "A"
                    },
                "url":
                    {
                        "@host": "test1.com",
                        "@method": "GET",
                        "@uri": "/test/72t0jjhmv7takwvisfnz_eejvf_h6v2ix/",
                        "@user_agent": ""
                    }
            }
    }
    expected_outputs_network = {'TCP': {'IP': ['1.1.1.1', '1.0.1.0'], 'Port': ['443', '80']},
                                'UDP': {'IP': ['1.1.1.1'], 'Port': ['55']},
                                'DNS': {'Query': ['test.com'], 'Response': ['1.1.1.1.']}}
    outputs, feed_related_indicators, behavior = parse_file_report(reports=report, file_info={})
    assert expected_outputs_network == outputs.get('Network')
